import 'dotenv/config';
import { Worker } from 'bullmq';
import { redis, disconnectRedis, REDIS_KEY_PREFIX, setWorkerHeartbeat } from '@/lib/redis';
import { 
  SYNC_SOURCE_QUEUE, CHECK_SOURCE_QUEUE, NOTIFICATION_QUEUE, 
    NOTIFICATION_DELIVERY_QUEUE, NOTIFICATION_DELIVERY_PREMIUM_QUEUE, NOTIFICATION_DIGEST_QUEUE,
    CANONICALIZE_QUEUE, REFRESH_COVER_QUEUE, CHAPTER_INGEST_QUEUE, GAP_RECOVERY_QUEUE,
    syncSourceQueue, checkSourceQueue, notificationQueue,
    notificationDeliveryQueue, notificationDeliveryPremiumQueue, notificationDigestQueue,
    canonicalizeQueue, refreshCoverQueue, chapterIngestQueue, gapRecoveryQueue
  } from '@/lib/queues';
import { processPollSource } from './processors/poll-source.processor';
import { processChapterIngest } from './processors/chapter-ingest.processor';
import { processCheckSource } from './processors/check-source.processor';
import { processNotification } from './processors/notification.processor';
import { processNotificationDelivery } from './processors/notification-delivery.processor';
import { processNotificationDigest } from './processors/notification-digest.processor';
import { processCanonicalize } from './processors/canonicalize.processor';
import { processRefreshCover } from './processors/refresh-cover.processor';
import { processGapRecovery } from './processors/gap-recovery.processor';
import { runMasterScheduler } from './schedulers/master.scheduler';

console.log('[Workers] Starting...');

// Canonicalization Worker
const canonicalizeWorker = new Worker(
  CANONICALIZE_QUEUE,
  processCanonicalize,
  { 
    connection: redis,
    prefix: REDIS_KEY_PREFIX,
    concurrency: 2,
  }
);

// Poll Source Worker
const pollSourceWorker = new Worker(
  SYNC_SOURCE_QUEUE,
  processPollSource,
  { 
    connection: redis,
    prefix: REDIS_KEY_PREFIX,
    concurrency: 20, // Increased for high-throughput polling
    limiter: {
      max: 10,
      duration: 1000,
    },
  }
);

// Chapter Ingest Worker
const chapterIngestWorker = new Worker(
  CHAPTER_INGEST_QUEUE,
  processChapterIngest,
  { 
    connection: redis,
    prefix: REDIS_KEY_PREFIX,
    concurrency: 10, // Increased for DB-bound ingestion
  }
);

// Check Source Worker
const checkSourceWorker = new Worker(
  CHECK_SOURCE_QUEUE,
  processCheckSource,
  { 
    connection: redis,
    prefix: REDIS_KEY_PREFIX,
    concurrency: 2,
    limiter: {
      max: 3,
      duration: 1000,
    },
  }
);

// Notification Worker
const notificationWorker = new Worker(
  NOTIFICATION_QUEUE,
  processNotification,
  { 
    connection: redis,
    prefix: REDIS_KEY_PREFIX,
    concurrency: 3,
  }
);

// Notification Delivery Worker (Free)
const notificationDeliveryWorker = new Worker(
  NOTIFICATION_DELIVERY_QUEUE,
  processNotificationDelivery,
  { 
    connection: redis,
    prefix: REDIS_KEY_PREFIX,
    concurrency: 5, // 3:1 ratio (Free: 5, Premium: 15)
  }
);

// Notification Delivery Worker (Premium)
const notificationDeliveryPremiumWorker = new Worker(
  NOTIFICATION_DELIVERY_PREMIUM_QUEUE,
  processNotificationDelivery,
  { 
    connection: redis,
    prefix: REDIS_KEY_PREFIX,
    concurrency: 15, // 3:1 ratio (Free: 5, Premium: 15)
    limiter: {
      max: 1000,
      duration: 60000, // Max 1000 per minute as per design
    },
  }
);

// Notification Digest Worker
const notificationDigestWorker = new Worker(
  NOTIFICATION_DIGEST_QUEUE,
  processNotificationDigest,
  { 
    connection: redis,
    prefix: REDIS_KEY_PREFIX,
    concurrency: 1, // Keep it low to avoid DB contention during batch processing
  }
);

// Refresh Cover Worker
const refreshCoverWorker = new Worker(
  REFRESH_COVER_QUEUE,
  processRefreshCover,
  {
    connection: redis,
    prefix: REDIS_KEY_PREFIX,
    concurrency: 1,
    limiter: {
      max: 1,
      duration: 1000,
    },
  }
);

// Gap Recovery Worker
const gapRecoveryWorker = new Worker(
  GAP_RECOVERY_QUEUE,
  processGapRecovery,
  {
    connection: redis,
    prefix: REDIS_KEY_PREFIX,
    concurrency: 1,
  }
);

// Heartbeat interval - tells the API that workers are online
const HEARTBEAT_INTERVAL = 5 * 1000; // 5 seconds
let heartbeatInterval: NodeJS.Timeout | null = null;

async function startHeartbeat() {
  // Send initial heartbeat
  await setWorkerHeartbeat();
  console.log('[Workers] Initial heartbeat sent');
  
  // Send periodic heartbeats
  heartbeatInterval = setInterval(async () => {
    try {
      await setWorkerHeartbeat();
      console.log('[Workers] Heartbeat sent');
    } catch (error) {
      console.error('[Workers] Failed to send heartbeat:', error);
    }
  }, HEARTBEAT_INTERVAL);
}

// Scheduler interval
const SCHEDULER_INTERVAL = 5 * 60 * 1000; // 5 minutes
const SCHEDULER_LOCK_KEY = `${REDIS_KEY_PREFIX}scheduler:lock`;
const SCHEDULER_LOCK_TTL = 360; // 6 minutes lock TTL (slightly longer than interval)
const WORKER_GLOBAL_LOCK_KEY = `${REDIS_KEY_PREFIX}workers:global`;
const WORKER_GLOBAL_LOCK_TTL = 60; // 60 seconds (short TTL for crash-safety)

let schedulerInterval: NodeJS.Timeout | null = null;
let globalLockHeartbeat: NodeJS.Timeout | null = null;

/**
 * Acquire global worker lock to ensure only one worker process runs.
 */
async function acquireGlobalLock(): Promise<boolean> {
  try {
    const result = await redis.set(WORKER_GLOBAL_LOCK_KEY, process.pid.toString(), 'EX', WORKER_GLOBAL_LOCK_TTL, 'NX');
    if (result === 'OK') {
      // Start heartbeat to keep the lock alive
      globalLockHeartbeat = setInterval(async () => {
        try {
          // Extend TTL
          await redis.expire(WORKER_GLOBAL_LOCK_KEY, WORKER_GLOBAL_LOCK_TTL);
        } catch (error) {
          console.error('[Workers] Failed to extend global lock TTL:', error);
        }
      }, (WORKER_GLOBAL_LOCK_TTL / 2) * 1000);
      return true;
    }
    return false;
  } catch (error) {
    console.error('[Workers] Failed to acquire global lock:', error);
    return false;
  }
}

/**
 * Acquire distributed lock for scheduler.
 * Only one worker instance should run the scheduler at a time.
 * Uses Redis SET NX EX for atomic lock acquisition.
 */
async function acquireSchedulerLock(): Promise<boolean> {
  try {
    const result = await redis.set(SCHEDULER_LOCK_KEY, process.pid.toString(), 'EX', SCHEDULER_LOCK_TTL, 'NX');
    return result === 'OK';
  } catch (error) {
    console.error('[Scheduler] Failed to acquire lock:', error);
    return false;
  }
}

async function startScheduler() {
  console.log('[Scheduler] Starting master scheduler loop...');
  
  const runScheduler = async () => {
    const hasLock = await acquireSchedulerLock();
    if (hasLock) {
      try {
        await runMasterScheduler();
      } catch (error) {
        console.error('[Scheduler] Error in master scheduler:', error);
      }
    } else {
      console.log('[Scheduler] Another instance is already running the scheduler.');
    }
  };

  // Run immediately
  await runScheduler();
  
  // Schedule periodic runs
  schedulerInterval = setInterval(runScheduler, SCHEDULER_INTERVAL);
}

async function start() {
  // 1. Acquire global lock
  const hasGlobalLock = await acquireGlobalLock();
  if (!hasGlobalLock) {
    console.error('[Workers] Another worker instance is already running. Exiting to avoid duplicate execution.');
    process.exit(1);
  }
  console.log('[Workers] Acquired global lock');

  // Start heartbeat and scheduler
  await startHeartbeat();
  await startScheduler();
  
  console.log('[Workers] Started');
  console.log('[Workers] Active and listening for jobs');
}

// Graceful shutdown
async function shutdown(signal: string) {
  console.log(`[Workers] Received ${signal}, shutting down gracefully...`);
  
  // Release global lock
  try {
    await redis.del(WORKER_GLOBAL_LOCK_KEY);
    console.log('[Workers] Global lock released');
  } catch (error) {
    console.error('[Workers] Failed to release global lock:', error);
  }

  // Stop heartbeat
  if (heartbeatInterval) {
    clearInterval(heartbeatInterval);
  }

  // Stop global lock heartbeat
  if (globalLockHeartbeat) {
    clearInterval(globalLockHeartbeat);
  }
  
  // Stop scheduler
  if (schedulerInterval) {
    clearInterval(schedulerInterval);
  }

  // Close workers (waits for current jobs to finish)
  await Promise.all([
    canonicalizeWorker.close(),
    pollSourceWorker.close(),
    chapterIngestWorker.close(),
    checkSourceWorker.close(),
    notificationWorker.close(),
    notificationDeliveryWorker.close(),
    notificationDeliveryPremiumWorker.close(),
    notificationDigestWorker.close(),
    refreshCoverWorker.close(),
  ]);

  // Close queues
  await Promise.all([
    syncSourceQueue.close(),
    checkSourceQueue.close(),
    notificationQueue.close(),
    notificationDeliveryQueue.close(),
    notificationDeliveryPremiumQueue.close(),
    notificationDigestQueue.close(),
    canonicalizeQueue.close(),
    refreshCoverQueue.close(),
    chapterIngestQueue.close(),
  ]);

  // Disconnect Redis
  await disconnectRedis();
  
  console.log('[Workers] Shutdown complete');
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Worker event handlers with detailed logging
pollSourceWorker.on('completed', (job) => {
  console.log(`[PollSource] Job ${job.id} completed`);
});

pollSourceWorker.on('failed', (job, err) => {
  console.error(`[PollSource] Job ${job?.id} failed:`, err.message);
});

pollSourceWorker.on('active', (job) => {
  console.log(`[PollSource] Job ${job.id} started processing`);
});

chapterIngestWorker.on('completed', (job) => {
  console.log(`[ChapterIngest] Job ${job.id} completed`);
});

chapterIngestWorker.on('failed', (job, err) => {
  console.error(`[ChapterIngest] Job ${job?.id} failed:`, err.message);
});

chapterIngestWorker.on('active', (job) => {
  console.log(`[ChapterIngest] Job ${job.id} started processing`);
});

checkSourceWorker.on('completed', (job) => {
  console.log(`[CheckSource] Job ${job.id} completed`);
});

checkSourceWorker.on('failed', (job, err) => {
  console.error(`[CheckSource] Job ${job?.id} failed:`, err.message);
});

checkSourceWorker.on('active', (job) => {
  console.log(`[CheckSource] Job ${job.id} started processing`);
});

notificationWorker.on('completed', (job) => {
  console.log(`[Notification] Job ${job.id} completed`);
});

notificationWorker.on('failed', (job, err) => {
  console.error(`[Notification] Job ${job?.id} failed:`, err.message);
});

notificationDeliveryWorker.on('completed', (job) => {
  console.log(`[NotificationDelivery] Job ${job.id} completed`);
});

notificationDeliveryWorker.on('failed', (job, err) => {
  console.error(`[NotificationDelivery] Job ${job?.id} failed:`, err.message);
});

notificationDeliveryWorker.on('active', (job) => {
  console.log(`[NotificationDelivery] Job ${job.id} started processing`);
});

canonicalizeWorker.on('completed', (job) => {
  console.log(`[Canonicalize] Job ${job.id} completed`);
});

canonicalizeWorker.on('failed', (job, err) => {
  console.error(`[Canonicalize] Job ${job?.id} failed:`, err.message);
});

canonicalizeWorker.on('active', (job) => {
  console.log(`[Canonicalize] Job ${job.id} started processing`);
});

refreshCoverWorker.on('completed', (job) => {
  console.log(`[RefreshCover] Job ${job.id} completed`);
});

refreshCoverWorker.on('failed', (job, err) => {
  console.error(`[RefreshCover] Job ${job?.id} failed:`, err.message);
});

refreshCoverWorker.on('active', (job) => {
  console.log(`[RefreshCover] Job ${job.id} started processing`);
});

// Redis Self-Check - ensures worker crashes if Redis is unreachable for an extended period
// This allows PM2 to manage restarts and avoids "zombie" workers
let failedPings = 0;
setInterval(async () => {
  try {
    const redisPing = await redis.ping();
    if (redisPing === 'PONG') {
      failedPings = 0;
      return;
    }
    failedPings++;
  } catch (error) {
    failedPings++;
  }

  if (failedPings >= 3) {
    console.error('[Workers] Redis consistently unavailable – exiting worker to allow PM2 restart');
    process.exit(1);
  }
}, 10000);

// Start heartbeat and scheduler
start().catch(error => {
  console.error('[Workers] Fatal error during startup:', error);
  process.exit(1);
});
