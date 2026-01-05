import { Job } from 'bullmq';
import { prisma } from '@/lib/prisma';
import { notificationDeliveryQueue, notificationDeliveryPremiumQueue, notificationQueue, isQueueHealthy } from '@/lib/queues';
import { shouldNotifyChapter } from '@/lib/notifications-throttling';
import { z } from 'zod';
import { redis, REDIS_KEY_PREFIX } from '@/lib/redis';

const NotificationJobDataSchema = z.object({
  seriesId: z.string().uuid(),
  sourceId: z.string().uuid(),
  sourceName: z.string().optional(),
  chapterNumber: z.number(),
  chapterNumbers: z.array(z.number()).optional(), // Added for coalescing
  newChapterCount: z.number().int().positive(),
  cursor: z.string().uuid().optional(),
});

export type NotificationJobData = z.infer<typeof NotificationJobDataSchema>;

const BATCH_SIZE = 1000;
const COALESCE_WINDOW_MS = 15000; // 15 seconds to group multiple chapters

/**
 * Master Notification Processor (Fan-out)
 */
export async function processNotification(job: Job<NotificationJobData>) {
  const parseResult = NotificationJobDataSchema.safeParse(job.data);
  if (!parseResult.success) {
    console.error(`[Notification-Master] Invalid payload: ${parseResult.error.message}`);
    return;
  }

  const { seriesId, sourceId, sourceName, chapterNumber, newChapterCount, cursor } = parseResult.data;
  let { chapterNumbers = [chapterNumber] } = parseResult.data;

  // 1. Coalescing Logic (Skip if this is already a fan-out continuation)
  if (!cursor) {
    const coalesceKey = `${REDIS_KEY_PREFIX}notif:coalesce:${seriesId}`;
    const bufferKey = `${REDIS_KEY_PREFIX}notif:buffer:${seriesId}`;

    // Try to set the coalesce lock
    const isFirst = await redis.set(coalesceKey, 'locked', 'PX', COALESCE_WINDOW_MS, 'NX');
    
    if (isFirst !== 'OK') {
      // Not the first job in the window. Append our chapter to the buffer and exit.
      await redis.sadd(bufferKey, chapterNumber.toString());
      await redis.expire(bufferKey, 30); // 30s TTL for safety
      console.log(`[Notification-Master] Coalescing chapter ${chapterNumber} for series ${seriesId}`);
      return;
    }

    // This IS the first job. Wait for the window to expire to collect all chapters.
    await new Promise(resolve => setTimeout(resolve, COALESCE_WINDOW_MS));

    // Pull all collected chapters from the buffer
    const bufferedChapters = await redis.smembers(bufferKey);
    if (bufferedChapters.length > 0) {
      const additionalNumbers = bufferedChapters.map(Number);
      chapterNumbers = Array.from(new Set([...chapterNumbers, ...additionalNumbers])).sort((a, b) => a - b);
      await redis.del(bufferKey);
    }
  }

  // 2. Fetch the source name if not provided
  let resolvedSourceName = sourceName;
  if (!resolvedSourceName && !cursor) {
    const seriesSource = await prisma.seriesSource.findUnique({
      where: { id: sourceId },
      select: { source_name: true },
    });
    resolvedSourceName = seriesSource?.source_name;
  }

  // 2. Global Deduplication Check (for IMMEDIATE delivery)
  // Check the primary chapter or the highest in the batch
  const displayChapter = chapterNumbers[chapterNumbers.length - 1];
  const isFirstSource = await shouldNotifyChapter(seriesId, displayChapter);

    // 3. Backpressure Check
    const isHealthy = await isQueueHealthy(notificationDeliveryQueue, 10000);
    if (!isHealthy) {
      console.warn(`[Notification-Master] Delivery queue backpressure detected. Delaying fan-out.`);
      await job.moveToDelayed(Date.now() + 30000, job.token); // Retry in 30s
      throw new Error('BACKPRESSURE_PAUSE');
    }

    // 4. Fetch existing sources for this logical chapter to check for fallback availability
    const existingSources = await prisma.chapterSource.findMany({
      where: {
        logical_chapter: {
          series_id: seriesId,
          chapter_number: displayChapter,
        },
        is_available: true,
      },
      select: {
        series_source: {
          select: { source_name: true }
        }
      }
    });
    const availableSourceNames = new Set(existingSources.map(s => s.series_source.source_name));

    // 5. Fetch Subscribers
    const subscribers = await prisma.libraryEntry.findMany({
      where: {
        series_id: seriesId,
        notify_new_chapters: true,
        ...(cursor ? { user_id: { gt: cursor } } : {}),
        user: {
          chapter_reads_v2: {
            none: {
              chapter: {
                series_id: seriesId,
                chapter_number: displayChapter
              }
            }
          }
        }
      },
      select: {
        user_id: true,
        notification_mode: true,
        preferred_source: true,
        status: true,
        user: {
          select: {
            notification_digest: true,
            subscription_tier: true,
          },
        },
      },
      orderBy: {
        user_id: 'asc',
      },
      take: BATCH_SIZE,
    });

    if (subscribers.length === 0) {
      if (!cursor) console.log(`[Notification-Master] No subscribers for series ${seriesId}`);
      return;
    }

    const immediateFreeByPriority: Record<number, string[]> = { 0: [], 1: [], 2: [] };
    const immediatePremiumByPriority: Record<number, string[]> = { 0: [], 1: [], 2: [] };
    const bufferedSubscribers: typeof subscribers = [];

    // 6. Fan-out with Source Preference and Fallback Logic
    for (const sub of subscribers) {
      const mode = sub.notification_mode;
      const frequency = sub.user.notification_digest;
      const isPremium = sub.user.subscription_tier !== 'free';
      const preferredSource = sub.preferred_source;
      const currentSource = resolvedSourceName ?? sourceName;

      // PRIORITY CALCULATION (P0=0, P1=1, P2=2)
      let priority = 2; // Default P2
      if (sub.status === 'reading') {
        priority = 0; // P0
      } else if (sub.status === 'planned') {
        priority = 1; // P1
      } else if (sub.status) {
        // Any other followed status with notifications enabled is P0 (Followed series with new chapter)
        priority = 0;
      }

      const isImmediate = mode === 'immediate' || (mode === 'default' && frequency === 'immediate');
      const isMuted = mode === 'muted';

      if (isMuted) continue;

      // Check if user already notified for this logical chapter (Dedupe across sources)
      const userDedupeKey = `${REDIS_KEY_PREFIX}notif:sent:user:${sub.user_id}:chapter:${seriesId}:${displayChapter}`;
      const alreadyNotified = await redis.get(userDedupeKey);
      if (alreadyNotified) continue;

      // Source Preference Logic
      let shouldNotifyThisSource = false;

      if (preferredSource === currentSource) {
        // Direct match with preference
        shouldNotifyThisSource = true;
      } else if (!preferredSource && isFirstSource) {
        // No preference, take the first available source
        shouldNotifyThisSource = true;
      } else if (isFirstSource && preferredSource && !availableSourceNames.has(preferredSource)) {
        // FALLBACK: User has a preference, but the preferred source doesn't have this chapter.
        // We notify them using the first available source so they don't miss out.
        console.log(`[Notification-Master] Fallback trigger for user ${sub.user_id}: Preferred source ${preferredSource} missing chapter ${displayChapter}.`);
        shouldNotifyThisSource = true;
      }

      if (!shouldNotifyThisSource) continue;

      // Mark as notified in Redis (TTL 7 days)
      await redis.set(userDedupeKey, '1', 'EX', 7 * 24 * 60 * 60);

      if (isImmediate) {
        if (isPremium) {
          immediatePremiumByPriority[priority].push(sub.user_id);
        } else {
          immediateFreeByPriority[priority].push(sub.user_id);
        }
      } else {
        bufferedSubscribers.push(sub);
      }
    }

    // 7. Handle Immediate Notifications

  const commonPayload = {
    seriesId,
    sourceId,
    sourceName: resolvedSourceName ?? sourceName,
    chapterNumber: displayChapter,
    chapterNumbers, // Send the full batch to delivery worker
    newChapterCount: chapterNumbers.length,
  };

  // Dispatch by Priority
  for (const p of [0, 1, 2] as const) {
    const premiumIds = immediatePremiumByPriority[p];
    if (premiumIds.length > 0) {
      await notificationDeliveryPremiumQueue.add(
        `delivery-premium-p${p}-${seriesId}-${displayChapter}-${cursor || 'start'}`,
        {
          ...commonPayload,
          userIds: premiumIds,
          isPremium: true,
          priority: p,
        },
        {
          removeOnComplete: true,
          priority: p + 1, // BullMQ priority (lower is higher)
        }
      );
    }

    const freeIds = immediateFreeByPriority[p];
    if (freeIds.length > 0) {
      await notificationDeliveryQueue.add(
        `delivery-free-p${p}-${seriesId}-${displayChapter}-${cursor || 'start'}`,
        {
          ...commonPayload,
          userIds: freeIds,
          isPremium: false,
          priority: p,
        },
        {
          removeOnComplete: true,
          priority: (p + 1) * 10, // BullMQ priority
        }
      );
    }
  }

  // 6. Handle Buffered Notifications (Digests)
  if (bufferedSubscribers.length > 0) {
    const source = resolvedSourceName ?? sourceName ?? 'Unknown';
    
    // Upsert each chapter in the batch into the digest buffer
    for (const chNum of chapterNumbers) {
      await Promise.all(bufferedSubscribers.map(sub => 
        prisma.$executeRaw`
          INSERT INTO notification_digest_buffer (user_id, series_id, chapter_number, source_names, updated_at)
          VALUES (${sub.user_id}::uuid, ${seriesId}::uuid, ${chNum}, ARRAY[${source}], now())
          ON CONFLICT (user_id, series_id, chapter_number, flushed_at) WHERE flushed_at IS NULL
          DO UPDATE SET 
            source_names = (
              SELECT array_agg(DISTINCT x) 
              FROM unnest(notification_digest_buffer.source_names || EXCLUDED.source_names) t(x)
            ),
            updated_at = now()
        `
      )).catch((e: any) => console.error('[Notification-Master] Digest buffer upsert failed', e));
    }
  }

  console.log(`[Notification-Master] Processed ${subscribers.length} users for chapters [${chapterNumbers.join(',')}]. Immediate: ${immediatePremiumUserIds.length + immediateFreeUserIds.length}, Buffered: ${bufferedSubscribers.length}`);

  // 7. Recursive Fan-out
  if (subscribers.length === BATCH_SIZE) {
    const nextCursor = subscribers[subscribers.length - 1].user_id;
    await notificationQueue.add(
      `fanout-${seriesId}-${displayChapter}-${nextCursor}`,
      {
        ...job.data,
        sourceName: resolvedSourceName ?? sourceName,
        chapterNumbers, // Pass the coalesced batch to the next cursor
        cursor: nextCursor,
      },
      {
        jobId: `fanout-${seriesId}-${displayChapter}-${nextCursor}`,
      }
    );
  }
}
