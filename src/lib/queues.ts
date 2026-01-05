import { Queue } from 'bullmq';
import { redis, REDIS_KEY_PREFIX, redisMode } from './redis';

export const SYNC_SOURCE_QUEUE = 'sync-source';
export const CHECK_SOURCE_QUEUE = 'check-source';
export const NOTIFICATION_QUEUE = 'notifications';
export const NOTIFICATION_DELIVERY_QUEUE = 'notification-delivery';
export const NOTIFICATION_DELIVERY_PREMIUM_QUEUE = 'notification-delivery-premium';
export const NOTIFICATION_DIGEST_QUEUE = 'notification-digest';
export const CANONICALIZE_QUEUE = 'canonicalize';
export const REFRESH_COVER_QUEUE = 'refresh-cover';
export const CHAPTER_INGEST_QUEUE = 'chapter-ingest';
export const GAP_RECOVERY_QUEUE = 'gap-recovery';

/**
 * Queue options using the shared Redis singleton instance.
 * This ensures all queues share a single connection to Redis,
 * preventing connection exhaustion.
 * Supports both single-node and Sentinel modes automatically.
 */
const queueOptions = {
  connection: redis, // Uses the shared singleton Redis instance
  prefix: REDIS_KEY_PREFIX,
};

console.log('[Queues] Initializing with Redis mode: %s', redisMode);

// Singleton pattern for Next.js hot reload protection
const globalForQueues = globalThis as unknown as {
  syncSourceQueue: Queue | undefined;
  chapterIngestQueue: Queue | undefined;
  checkSourceQueue: Queue | undefined;
  notificationQueue: Queue | undefined;
  notificationDeliveryQueue: Queue | undefined;
  notificationDeliveryPremiumQueue: Queue | undefined;
  notificationDigestQueue: Queue | undefined;
  canonicalizeQueue: Queue | undefined;
  refreshCoverQueue: Queue | undefined;
  gapRecoveryQueue: Queue | undefined;
};

export const syncSourceQueue = globalForQueues.syncSourceQueue ?? new Queue(SYNC_SOURCE_QUEUE, {
  ...queueOptions,
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5000 },
    removeOnComplete: { count: 100, age: 3600 },
    removeOnFail: { count: 500, age: 86400 },
  },
});

export const chapterIngestQueue = globalForQueues.chapterIngestQueue ?? new Queue(CHAPTER_INGEST_QUEUE, {
  ...queueOptions,
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5000 },
    removeOnComplete: { count: 500, age: 3600 },
    removeOnFail: { count: 1000, age: 86400 },
  },
});

export const checkSourceQueue = globalForQueues.checkSourceQueue ?? new Queue(CHECK_SOURCE_QUEUE, {
  ...queueOptions,
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5000 },
    removeOnComplete: { count: 100, age: 3600 },
    removeOnFail: { count: 500, age: 86400 },
  },
});

export const notificationQueue = globalForQueues.notificationQueue ?? new Queue(NOTIFICATION_QUEUE, {
  ...queueOptions,
  defaultJobOptions: {
    attempts: 5,
    backoff: { type: 'exponential', delay: 1000 },
    removeOnComplete: { count: 100, age: 3600 },
    removeOnFail: { count: 500, age: 86400 },
  },
});

export const notificationDeliveryQueue = globalForQueues.notificationDeliveryQueue ?? new Queue(NOTIFICATION_DELIVERY_QUEUE, {
  ...queueOptions,
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5000 },
    removeOnComplete: { count: 500, age: 3600 },
    removeOnFail: { count: 1000, age: 86400 },
  },
});

export const notificationDeliveryPremiumQueue = globalForQueues.notificationDeliveryPremiumQueue ?? new Queue(NOTIFICATION_DELIVERY_PREMIUM_QUEUE, {
  ...queueOptions,
  defaultJobOptions: {
    attempts: 5,
    backoff: { type: 'exponential', delay: 1000 },
    removeOnComplete: { count: 1000, age: 3600 },
    removeOnFail: { count: 2000, age: 86400 },
  },
});

export const notificationDigestQueue = globalForQueues.notificationDigestQueue ?? new Queue(NOTIFICATION_DIGEST_QUEUE, {
  ...queueOptions,
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5000 },
    removeOnComplete: { count: 100, age: 3600 },
    removeOnFail: { count: 500, age: 86400 },
  },
});

export const canonicalizeQueue = globalForQueues.canonicalizeQueue ?? new Queue(CANONICALIZE_QUEUE, {
  ...queueOptions,
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5000 },
    removeOnComplete: { count: 100, age: 3600 },
    removeOnFail: { count: 500, age: 86400 },
  },
});

export const refreshCoverQueue = globalForQueues.refreshCoverQueue ?? new Queue(REFRESH_COVER_QUEUE, {
  ...queueOptions,
  defaultJobOptions: {
    attempts: 2,
    backoff: { type: 'exponential', delay: 10000 },
    removeOnComplete: { count: 50, age: 3600 },
    removeOnFail: { count: 100, age: 86400 },
  },
});

export const gapRecoveryQueue = globalForQueues.gapRecoveryQueue ?? new Queue(GAP_RECOVERY_QUEUE, {
  ...queueOptions,
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 10000 },
    removeOnComplete: { count: 100, age: 3600 },
    removeOnFail: { count: 500, age: 86400 },
  },
});

if (process.env.NODE_ENV !== 'production') {
  globalForQueues.syncSourceQueue = syncSourceQueue;
  globalForQueues.chapterIngestQueue = chapterIngestQueue;
  globalForQueues.checkSourceQueue = checkSourceQueue;
  globalForQueues.notificationQueue = notificationQueue;
  globalForQueues.notificationDeliveryQueue = notificationDeliveryQueue;
  globalForQueues.notificationDeliveryPremiumQueue = notificationDeliveryPremiumQueue;
  globalForQueues.canonicalizeQueue = canonicalizeQueue;
  globalForQueues.refreshCoverQueue = refreshCoverQueue;
  globalForQueues.gapRecoveryQueue = gapRecoveryQueue;
}

/**
 * Gets the overall system health for notifications.
 * Returns thresholds for circuit breaking.
 */
export async function getNotificationSystemHealth(): Promise<{ 
  totalWaiting: number; 
  isOverloaded: boolean;
  isCritical: boolean;
  isRejected: boolean;
}> {
  try {
    const freeCounts = await notificationDeliveryQueue.getJobCounts('waiting');
    const premiumCounts = await notificationDeliveryPremiumQueue.getJobCounts('waiting');
    const totalWaiting = freeCounts.waiting + premiumCounts.waiting;

    return {
      totalWaiting,
      isOverloaded: totalWaiting > 10000,
      isCritical: totalWaiting > 50000,
      isRejected: totalWaiting > 100000,
    };
  } catch (error) {
    console.error('[Queue] Health check failed:', error);
    return { totalWaiting: 0, isOverloaded: false, isCritical: false, isRejected: false };
  }
}

/**
 * Checks if a specific queue is healthy based on a waiting threshold.
 */
export async function isQueueHealthy(queue: Queue, threshold: number): Promise<boolean> {
  const counts = await queue.getJobCounts('waiting');
  return counts.waiting < threshold;
}
