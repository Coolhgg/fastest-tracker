import { notificationDeliveryQueue, notificationDeliveryPremiumQueue } from '@/lib/queues';

/**
 * Safety Monitor Scheduler
 * Implements anti-starvation and health checks for the notification system.
 */
export async function runSafetyMonitor() {
  console.log('[Safety-Monitor] Running health checks...');

  try {
    // 1. Check Free Queue Depth
    const freeQueueCounts = await notificationDeliveryQueue.getJobCounts('waiting', 'active', 'delayed');
    const freeWaiting = freeQueueCounts.waiting;
    
    // 2. Check Premium Queue Depth
    const premiumQueueCounts = await notificationDeliveryPremiumQueue.getJobCounts('waiting', 'active', 'delayed');
    const premiumWaiting = premiumQueueCounts.waiting;

    console.log(`[Safety-Monitor] Queue Depths - Free: ${freeWaiting}, Premium: ${premiumWaiting}`);

    // 3. Anti-Starvation Check (Free Queue)
    if (freeWaiting > 10000) {
      console.error(`[Safety-Monitor] CRITICAL: Free queue depth exceeded threshold (10,000). Current: ${freeWaiting}`);
    }

    // 4. Oldest Job Check (Free Queue)
    const oldestFreeJobs = await notificationDeliveryQueue.getJobs(['waiting'], 0, 0, true);
    if (oldestFreeJobs.length > 0) {
      const oldestJob = oldestFreeJobs[0];
      const ageMs = Date.now() - oldestJob.timestamp;
      const ageMinutes = ageMs / (1000 * 60);

      if (ageMinutes > 5) {
        console.error(`[Safety-Monitor] CRITICAL: Free queue oldest job age exceeded threshold (5 minutes). Current: ${ageMinutes.toFixed(2)}m`);
        // In a real system, we might trigger an auto-scaling event or promotion logic here.
      }
    }

    // 5. Worker Overload Logic (General)
    const totalWaiting = freeWaiting + premiumWaiting;
    if (totalWaiting > 50000) {
      console.warn(`[Safety-Monitor] WARNING: System-wide notification backlog detected. Total waiting: ${totalWaiting}`);
    }

    // 6. Redis Outage / Latency Check (Implicitly handled by BullMQ calls failing, but we can log)
    // BullMQ will throw if Redis is down.

  } catch (error) {
    console.error('[Safety-Monitor] Failed to run health checks:', error);
  }
}
