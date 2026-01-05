import { Job } from 'bullmq';
import { prisma } from '@/lib/prisma';
import { notificationQueue, gapRecoveryQueue } from '@/lib/queues';
import { Prisma } from '@prisma/client';
import { z } from 'zod';

const FEED_BATCH_WINDOW_HOURS = 24;

const ChapterIngestDataSchema = z.object({
  seriesSourceId: z.string().uuid(),
  seriesId: z.string().uuid(),
  chapterNumber: z.number(),
  chapterTitle: z.string().nullable(),
  chapterUrl: z.string().url(),
  publishedAt: z.string().nullable(),
  isRecovery: z.boolean().optional(),
});

export interface ChapterIngestData {
  seriesSourceId: string;
  seriesId: string;
  chapterNumber: number;
  chapterTitle: string | null;
  chapterUrl: string;
  publishedAt: string | null;
  isRecovery?: boolean;
}

interface SourceEntry {
  name: string;
  url: string;
  discovered_at: string;
}

export async function processChapterIngest(job: Job<ChapterIngestData>) {
  const parseResult = ChapterIngestDataSchema.safeParse(job.data);
  if (!parseResult.success) {
    throw new Error(`Invalid job payload: ${parseResult.error.message}`);
  }

  const { 
    seriesSourceId, 
    seriesId, 
    chapterNumber, 
    chapterTitle, 
    chapterUrl, 
    publishedAt,
    isRecovery = false
  } = parseResult.data;

  const chapterNumDecimal = new Prisma.Decimal(chapterNumber);

  const seriesSource = await prisma.seriesSource.findUnique({
    where: { id: seriesSourceId },
    select: { source_name: true },
  });
  const sourceName = seriesSource?.source_name ?? 'Unknown';

  await prisma.$transaction(async (tx) => {
    if (!isRecovery && chapterNumber > 1) {
      const prevChapter = await tx.logicalChapter.findUnique({
        where: {
          series_id_chapter_number: {
            series_id: seriesId,
            chapter_number: new Prisma.Decimal(chapterNumber - 1),
          },
        },
      });

      if (!prevChapter) {
        console.log(`[ChapterIngest] Gap detected before chapter ${chapterNumber} for series ${seriesId}. Enqueueing recovery.`);
        await gapRecoveryQueue.add(
          `gap-recovery-${seriesId}`,
          { seriesId },
          { 
            jobId: `gap-recovery-${seriesId}`,
            delay: 10000 
          }
        );
      }
    }

    let discoveredAt = new Date();
    if (isRecovery) {
      const nextChapterSource = await tx.chapterSource.findFirst({
        where: {
          logical_chapter: {
            series_id: seriesId,
            chapter_number: { gt: chapterNumDecimal },
          }
        },
        orderBy: {
          logical_chapter: { chapter_number: 'asc' }
        },
        select: { discovered_at: true }
      });

      if (nextChapterSource) {
        discoveredAt = new Date(nextChapterSource.discovered_at.getTime() - 1);
      }
    }

    const logicalChapter = await tx.logicalChapter.upsert({
      where: {
        series_id_chapter_number: {
          series_id: seriesId,
          chapter_number: chapterNumDecimal,
        },
      },
      update: {
        chapter_title: chapterTitle || undefined,
        published_at: publishedAt ? new Date(publishedAt) : undefined,
      },
      create: {
        series_id: seriesId,
        chapter_number: chapterNumDecimal,
        chapter_title: chapterTitle,
        published_at: publishedAt ? new Date(publishedAt) : null,
      },
    });

    const existingSource = await tx.chapterSource.findUnique({
      where: {
        series_source_id_chapter_id: {
          series_source_id: seriesSourceId,
          chapter_id: logicalChapter.id,
        },
      },
    });

    if (existingSource) {
      await tx.chapterSource.update({
        where: { id: existingSource.id },
        data: {
          chapter_url: chapterUrl,
          chapter_title: chapterTitle,
          source_published_at: publishedAt ? new Date(publishedAt) : undefined,
          is_available: true,
          last_checked_at: new Date(),
        },
      });
    } else {
      await tx.chapterSource.create({
        data: {
          chapter_id: logicalChapter.id,
          series_source_id: seriesSourceId,
          chapter_url: chapterUrl,
          chapter_title: chapterTitle,
          source_published_at: publishedAt ? new Date(publishedAt) : null,
          discovered_at: discoveredAt,
          is_available: true,
        },
      });

      await tx.seriesSource.update({
        where: { id: seriesSourceId },
        data: {
          source_chapter_count: { increment: 1 },
          sync_priority: 'HOT',
          next_check_at: new Date(Date.now() + 15 * 60 * 1000),
        },
      });
    }

    const existingChapter = await tx.chapter.findUnique({
      where: {
        series_source_id_chapter_number: {
          series_source_id: seriesSourceId,
          chapter_number: chapterNumDecimal,
        },
      },
    });

    if (existingChapter) {
      await tx.chapter.update({
        where: { id: existingChapter.id },
        data: {
          chapter_title: chapterTitle,
          chapter_url: chapterUrl,
          published_at: publishedAt ? new Date(publishedAt) : existingChapter.published_at,
          is_available: true,
        },
      });
    } else {
      await tx.chapter.create({
        data: {
          series_id: seriesId,
          series_source_id: seriesSourceId,
          chapter_number: chapterNumDecimal,
          chapter_title: chapterTitle,
          chapter_url: chapterUrl,
          published_at: publishedAt ? new Date(publishedAt) : null,
          discovered_at: discoveredAt,
        },
      });
    }

    const windowCutoff = new Date(Date.now() - FEED_BATCH_WINDOW_HOURS * 60 * 60 * 1000);
    
    const existingFeedEntry = await tx.feedEntry.findFirst({
      where: {
        series_id: seriesId,
        chapter_number: chapterNumDecimal,
        first_discovered_at: { gte: windowCutoff },
      },
    });

    const newSourceEntry: SourceEntry = {
      name: sourceName,
      url: chapterUrl,
      discovered_at: discoveredAt.toISOString(),
    };

    if (existingFeedEntry) {
      const existingSources = (existingFeedEntry.sources as SourceEntry[]) || [];
      const sourceExists = existingSources.some((s) => s.name === sourceName);
      
      if (!sourceExists) {
        await tx.feedEntry.update({
          where: { id: existingFeedEntry.id },
          data: {
            sources: [...existingSources, newSourceEntry],
            last_updated_at: new Date(),
            logical_chapter_id: logicalChapter.id,
          },
        });
      }
    } else {
      await tx.feedEntry.create({
        data: {
          series_id: seriesId,
          logical_chapter_id: logicalChapter.id,
          chapter_number: chapterNumDecimal,
          sources: [newSourceEntry],
          first_discovered_at: discoveredAt,
          last_updated_at: discoveredAt,
        },
      });
    }
  });

  const window = Math.floor(Date.now() / (2 * 60 * 1000));
  const notificationJobId = `notify-${seriesId}-${seriesSourceId}-${chapterNumber}-${window}`;

  await notificationQueue.add(
    notificationJobId,
    {
      seriesId,
      sourceId: seriesSourceId,
      chapterNumber,
      newChapterCount: 1,
    },
    { 
      jobId: notificationJobId,
      delay: isRecovery ? 30000 : 5000,
    }
  );
}
