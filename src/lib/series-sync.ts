import { prisma, withRetry } from "@/lib/prisma";
import { Prisma } from "@prisma/client";
import { ScrapedChapter } from "@/lib/scrapers";
import { updateSeriesBestCover } from "@/lib/cover-resolver";

export interface SyncOptions {
  forceUpdate?: boolean;
  skipLegacy?: boolean;
}

export async function syncChapters(
  seriesId: string,
  sourceId: string,
  sourceName: string,
  scrapedChapters: ScrapedChapter[],
  options: SyncOptions = {}
) {
  if (scrapedChapters.length === 0) return 0;

  // 1. Get the source record
  const seriesSource = await prisma.seriesSource.findUnique({
    where: { source_name_source_id: { source_name: sourceName, source_id: sourceId } },
  });

  if (!seriesSource) {
    throw new Error(`Series source ${sourceName}:${sourceId} not found`);
  }

  // 2. Perform upserts in batches to avoid transaction timeouts
  let newChaptersCount = 0;
  let maxChapterNumber = new Prisma.Decimal(0);
  const BATCH_SIZE = 50;

  for (let i = 0; i < scrapedChapters.length; i += BATCH_SIZE) {
    const batch = scrapedChapters.slice(i, i + BATCH_SIZE);
    
    await prisma.$transaction(async (tx) => {
      for (const ch of batch) {
        const chNum = new Prisma.Decimal(ch.chapterNumber);
        if (chNum.greaterThan(maxChapterNumber)) {
          maxChapterNumber = chNum;
        }

        // V2: Logical Chapter (Shared across sources)
        const logicalChapter = await tx.logicalChapter.upsert({
          where: {
            series_id_chapter_number: {
              series_id: seriesId,
              chapter_number: chNum,
            },
          },
          update: {
            chapter_title: ch.chapterTitle,
            published_at: ch.publishedAt || undefined,
          },
          create: {
            series_id: seriesId,
            chapter_number: chNum,
            chapter_title: ch.chapterTitle,
            published_at: ch.publishedAt || null,
          },
        });

        // V2: Chapter Source (Link logical chapter to this source)
        await tx.chapterSource.upsert({
          where: {
            series_source_id_chapter_id: {
              series_source_id: seriesSource.id,
              chapter_id: logicalChapter.id,
            },
          },
          update: {
            chapter_url: ch.chapterUrl,
            chapter_title: ch.chapterTitle,
            source_published_at: ch.publishedAt || undefined,
            is_available: true,
          },
          create: {
            chapter_id: logicalChapter.id,
            series_source_id: seriesSource.id,
            chapter_url: ch.chapterUrl,
            chapter_title: ch.chapterTitle,
            source_published_at: ch.publishedAt || null,
          },
        });

        // V1: Legacy Chapter (Directly coupled to source)
        if (!options.skipLegacy) {
          await tx.chapter.upsert({
            where: {
              series_source_id_chapter_number: {
                series_source_id: seriesSource.id,
                chapter_number: chNum,
              },
            },
            update: {
              chapter_title: ch.chapterTitle,
              chapter_url: ch.chapterUrl,
              published_at: ch.publishedAt || undefined,
              is_available: true,
            },
            create: {
              series_id: seriesId,
              series_source_id: seriesSource.id,
              chapter_number: chNum,
              chapter_title: ch.chapterTitle,
              chapter_url: ch.chapterUrl,
              published_at: ch.publishedAt || null,
            },
          });
        }

        newChaptersCount++;
      }
    }, { 
      timeout: 30000, // Increase timeout to 30s for large batches
      maxWait: 5000   // Max wait for connection pool
    });
  }

  // 3. Update source and series metadata (Final state)
  await prisma.$transaction(async (tx) => {
    // Update source heartbeat
    await tx.seriesSource.update({
      where: { id: seriesSource.id },
      data: {
        last_success_at: new Date(),
        last_checked_at: new Date(),
        failure_count: 0,
      },
    });

    // Update series metadata
    const series = await tx.series.findUnique({ where: { id: seriesId } });
    if (series) {
      const currentMax = series.latest_chapter ? new Prisma.Decimal(series.latest_chapter) : new Prisma.Decimal(0);
      if (maxChapterNumber.greaterThan(currentMax)) {
        await tx.series.update({
          where: { id: seriesId },
          data: {
            latest_chapter: maxChapterNumber,
            last_chapter_at: new Date(),
            updated_at: new Date(),
          },
        });
      }
    }
  });

  // 3. Post-sync optimizations (Outside transaction)
  try {
    // Ensure best cover is up to date
    await updateSeriesBestCover(seriesId);
  } catch (err) {
    console.error(`[Sync] Failed to update best cover for ${seriesId}:`, err);
  }

  return newChaptersCount;
}
