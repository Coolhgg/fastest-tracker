import { Job } from 'bullmq';
import { prisma } from '@/lib/prisma';
import { scrapers, ScraperError, validateSourceUrl } from '@/lib/scrapers';
import { chapterIngestQueue } from '@/lib/queues';
import { sourceRateLimiter } from '@/lib/rate-limiter';
import { z } from 'zod';

const MAX_CONSECUTIVE_FAILURES = 5;
const RATE_LIMIT_TIMEOUT_MS = 60000; // 60s max wait for rate limit

const PollSourceDataSchema = z.object({
  seriesSourceId: z.string().uuid(),
});

export interface PollSourceData {
  seriesSourceId: string;
}

export async function processPollSource(job: Job<PollSourceData>) {
  // Validate job payload
  const parseResult = PollSourceDataSchema.safeParse(job.data);
  if (!parseResult.success) {
    throw new Error(`Invalid job payload: ${parseResult.error.message}`);
  }

  const { seriesSourceId } = parseResult.data;

  const source = await prisma.seriesSource.findUnique({
    where: { id: seriesSourceId },
    include: { series: true }
  });

  if (!source) {
    console.warn(`[PollSource] Source ${seriesSourceId} not found, skipping`);
    return;
  }

  // Circuit breaker: skip if too many consecutive failures
  if (source.failure_count >= MAX_CONSECUTIVE_FAILURES) {
    console.warn(`[PollSource] Circuit breaker open for ${seriesSourceId} (${source.failure_count} failures)`);
    await prisma.seriesSource.update({
      where: { id: source.id },
      data: {
        sync_priority: 'COLD',
        next_check_at: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24hr
      }
    });
    return;
  }

  // Validate source URL
  if (!validateSourceUrl(source.source_url)) {
    console.error(`[PollSource] Invalid source URL for ${seriesSourceId}`);
    await prisma.seriesSource.update({
      where: { id: source.id },
      data: {
        failure_count: { increment: 1 },
        last_checked_at: new Date(),
      }
    });
    return;
  }

  const scraper = scrapers[source.source_name.toLowerCase()];
  if (!scraper) {
    console.error(`[PollSource] No scraper for source ${source.source_name}`);
    return;
  }

  // ========================================
  // RATE LIMITING: Acquire token before scraping
  // This ensures we don't exceed per-source limits
  // ========================================
  const sourceName = source.source_name.toLowerCase();
  console.log(`[PollSource] Waiting for rate limit token for ${sourceName}...`);
  
  const tokenAcquired = await sourceRateLimiter.acquireToken(sourceName, RATE_LIMIT_TIMEOUT_MS);
  
  if (!tokenAcquired) {
    // Rate limit timeout - reschedule job for later
    console.warn(`[PollSource] Rate limit timeout for ${sourceName}, rescheduling`);
    // Don't throw - just return and let the scheduler pick it up next cycle
    // This prevents job starvation by not blocking the queue
    await prisma.seriesSource.update({
      where: { id: source.id },
      data: {
        next_check_at: new Date(Date.now() + 5 * 60 * 1000), // Retry in 5 min
      }
    });
    return;
  }

  try {
    console.log(`[PollSource] Polling ${source.source_name} for ${source.series.title}...`);
    const scrapedData = await scraper.scrapeSeries(source.source_id);
    
    // For each chapter, enqueue an ingestion job
    const ingestJobs = scrapedData.chapters.map(chapter => {
      const chapterNumberStr = chapter.chapterNumber.toString();
      // Deduplication key: sourceId:chapterNumber
      const dedupKey = `${source.id}:${chapterNumberStr}`;
      
      return {
        name: `ingest-${dedupKey}`,
        data: {
          seriesSourceId: source.id,
          seriesId: source.series_id,
          chapterNumber: chapter.chapterNumber,
          chapterTitle: chapter.chapterTitle || null,
          chapterUrl: chapter.chapterUrl,
          publishedAt: chapter.publishedAt ? chapter.publishedAt.toISOString() : null,
        },
        opts: {
          jobId: `ingest-${dedupKey}`, // BullMQ native deduplication
          attempts: 3,
          backoff: {
            type: 'exponential',
            delay: 1000,
          }
        }
      };
    });

    if (ingestJobs.length > 0) {
      await chapterIngestQueue.addBulk(ingestJobs);
      console.log(`[PollSource] Enqueued ${ingestJobs.length} ingestion jobs for ${source.series.title}`);
    }

    // Update source status
    await prisma.seriesSource.update({
      where: { id: source.id },
      data: {
        last_checked_at: new Date(),
        last_success_at: new Date(),
        failure_count: 0,
      }
    });

  } catch (error) {
    const isRetryable = error instanceof ScraperError ? error.isRetryable : true;
    
    console.error(`[PollSource] Error polling source ${source.id}:`, error);
    
    await prisma.seriesSource.update({
      where: { id: source.id },
      data: {
        last_checked_at: new Date(),
        failure_count: { increment: 1 },
      }
    });

    if (isRetryable) {
      throw error;
    }
  }
}
