import { Job } from 'bullmq';
import { prisma } from '@/lib/prisma';
import { supabaseAdmin } from '@/lib/supabase/admin';
import { isValidCoverUrl, isMangaDexPlaceholder } from '@/lib/cover-resolver';

interface CanonicalizeJobData {
  title: string;
  source_name: string;
  source_id: string;
  source_url: string;
  mangadex_id?: string;
  alternative_titles?: string[];
  description?: string;
  cover_url?: string;
  type: string;
  status?: string;
  genres?: string[];
  tags?: string[];  // Themes/tags from MangaDex
  content_rating?: string;
  confidence?: number;
}

export async function processCanonicalize(job: Job<CanonicalizeJobData>) {
  const { 
    title, 
    source_name, 
    source_id, 
    source_url, 
    mangadex_id, 
    alternative_titles = [], 
    description, 
    cover_url,
    type,
    status,
    genres = [],
    tags = [],  // Themes/tags from MangaDex
    content_rating,
    confidence
  } = job.data;

  console.log(`[Canonicalize] Job ${job.id} started processing: ${source_name}:${source_id} - "${title}" (genres: ${genres.length}, tags: ${tags.length})`);

  const result = await prisma.$transaction(async (tx) => {
    let series = null;
    let created = false;

    if (mangadex_id) {
      series = await tx.series.findUnique({
        where: { mangadex_id },
      });
      if (series) {
        console.log(`[Canonicalize] Matched by mangadex_id: ${series.title} (ID: ${series.id})`);
      }
    }

    if (!series) {
      const existingSource = await tx.seriesSource.findUnique({
        where: {
          source_name_source_id: {
            source_name,
            source_id,
          },
        },
        include: { series: true },
      });
      if (existingSource) {
        series = existingSource.series;
        console.log(`[Canonicalize] Matched by source link: ${series.title} (ID: ${series.id})`);
      }
    }

    if (!series) {
      series = await tx.series.findFirst({
        where: {
          title: {
            equals: title,
            mode: 'insensitive',
          },
        },
      });
      if (series) {
        console.log(`[Canonicalize] Matched by title: ${series.title} (ID: ${series.id})`);
      }
    }

    const currentAltTitles = (series?.alternative_titles as string[]) || [];
    const mergedAltTitles = Array.from(new Set([...currentAltTitles, ...alternative_titles, title]));

    const validIncomingCover = isValidCoverUrl(cover_url) ? cover_url : null;
    const incomingIsPlaceholder = isMangaDexPlaceholder(cover_url);
    const existingCoverValid = isValidCoverUrl(series?.cover_url);
    const existingIsPlaceholder = isMangaDexPlaceholder(series?.cover_url);

    // Merge existing tags with new tags
    const existingTags = (series?.tags as string[]) || [];
    const mergedTags = Array.from(new Set([...existingTags, ...tags]));

    if (series) {
      let newCoverUrl: string | null = series.cover_url ?? null;

      if (source_name === 'mangadex') {
        if (validIncomingCover && !incomingIsPlaceholder) {
          newCoverUrl = validIncomingCover;
        } else if (existingCoverValid && !existingIsPlaceholder) {
          newCoverUrl = series.cover_url;
        } else if (validIncomingCover) {
          newCoverUrl = validIncomingCover;
        }
      } else if (validIncomingCover && !existingCoverValid) {
        newCoverUrl = validIncomingCover;
      } else if (validIncomingCover && !incomingIsPlaceholder && existingIsPlaceholder) {
        newCoverUrl = validIncomingCover;
      }

      const needsUpdate = 
        (!series.mangadex_id && mangadex_id) ||
        (!series.description && description) ||
        (series.cover_url !== newCoverUrl) ||
        (status && series.status !== status) ||
        (content_rating && series.content_rating !== content_rating) ||
        (tags.length > 0 && existingTags.length === 0);  // Update if we have new tags

      if (needsUpdate) {
        series = await tx.series.update({
          where: { id: series.id },
          data: {
            mangadex_id: series.mangadex_id || mangadex_id,
            description: series.description || description,
            cover_url: newCoverUrl,
            alternative_titles: mergedAltTitles,
            status: series.status || status,
            genres: series.genres.length > 0 ? series.genres : genres,
            tags: mergedTags.length > 0 ? mergedTags : (series.tags || []),  // Save tags/themes
            content_rating: content_rating || series.content_rating,
          },
        });
        console.log(`[Canonicalize] Updated existing series: ${series.title} (tags: ${mergedTags.length})`);
      }
    } else {
      console.log(`[Canonicalize] Creating new canonical series: "${title}" with ${tags.length} tags`);
      series = await tx.series.create({
        data: {
          title,
          mangadex_id,
          alternative_titles: mergedAltTitles,
          description,
          cover_url: validIncomingCover,
          type,
          status,
          genres,
          tags,  // Save tags/themes on creation
          content_rating,
        },
      });
      created = true;
      console.log(`[Canonicalize] Created new series: ${series.title} (ID: ${series.id}, tags: ${tags.length})`);
    }

    await tx.seriesSource.upsert({
      where: {
        source_name_source_id: {
          source_name,
          source_id,
        },
      },
      update: {
        series_id: series.id,
        source_url,
        source_title: title,
        match_confidence: confidence,
        cover_url: validIncomingCover || undefined,
        cover_updated_at: validIncomingCover ? new Date() : undefined,
      },
      create: {
        series_id: series.id,
        source_name,
        source_id,
        source_url,
        source_title: title,
        match_confidence: confidence,
        sync_priority: 'COLD',
        cover_url: validIncomingCover || null,
        cover_updated_at: validIncomingCover ? new Date() : null,
      },
    });

    return { series, created };
  });

  console.log(`[Canonicalize] Job ${job.id} completed for "${result.series.title}" (created: ${result.created})`);

  console.log(`[Canonicalize] Emitting series.available event for "${result.series.title}"`);
  try {
    await supabaseAdmin
      .channel('public:series')
      .send({
        type: 'broadcast',
        event: 'series.available',
        payload: {
          series_id: result.series.id,
          mangadex_id,
          title: result.series.title,
          created: result.created
        }
      });
    console.log(`[Canonicalize] series.available event emitted successfully`);
  } catch (err) {
    console.error(`[Canonicalize] Failed to emit series.available event:`, err);
  }

  return { series_id: result.series.id, created: result.created };
}
