import { prisma } from '@/lib/prisma';
import { syncSourceQueue } from '@/lib/queues';
import { runCoverRefreshScheduler } from './cover-refresh.scheduler';
import { runDeferredSearchScheduler } from './deferred-search.scheduler';
import { runNotificationDigestScheduler } from './notification-digest.scheduler';
import { runSafetyMonitor } from './safety-monitor.scheduler';

export const SYNC_INTERVALS = {
  HOT: 15 * 60 * 1000,      // 15 mins
  WARM: 4 * 60 * 60 * 1000,  // 4 hours
  COLD: 24 * 60 * 60 * 1000, // 24 hours
} as const;

type SyncPriority = keyof typeof SYNC_INTERVALS;

/**
 * Maintenance task to update sync_priority based on activity and popularity
 * HOT: Updated < 24h ago OR > 100 readers
 * WARM: Updated < 7d ago
 * COLD: Stale/Completed
 */
async function maintenancePriorities() {
  const now = new Date();
  const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

  console.log('[Scheduler] Running priority maintenance...');

  // 1. Promote to HOT: Series with > 100 readers
  const popularPromotions = await prisma.seriesSource.updateMany({
    where: {
      sync_priority: { not: 'HOT' },
      series: {
        stats: {
          total_readers: { gt: 100 }
        }
      }
    },
    data: { sync_priority: 'HOT' }
  });

  // 2. Downgrade HOT -> WARM: No updates in 24h AND <= 100 readers
  const hotDowngrades = await prisma.seriesSource.updateMany({
    where: {
      sync_priority: 'HOT',
      last_success_at: { lt: oneDayAgo },
      series: {
        OR: [
          { stats: { total_readers: { lte: 100 } } },
          { stats: null }
        ]
      }
    },
    data: { sync_priority: 'WARM' }
  });

  // 3. Downgrade WARM -> COLD: No updates in 7 days
  const warmDowngrades = await prisma.seriesSource.updateMany({
    where: {
      sync_priority: 'WARM',
      last_success_at: { lt: sevenDaysAgo }
    },
    data: { sync_priority: 'COLD' }
  });

  console.log(`[Scheduler] Maintenance complete: ${popularPromotions.count} promoted to HOT, ${hotDowngrades.count} downgraded to WARM, ${warmDowngrades.count} downgraded to COLD`);
}

export async function runMasterScheduler() {
  console.log('[Scheduler] Running master scheduler...');

  const now = new Date();

  // 0. Priority Maintenance
  try {
    await maintenancePriorities();
  } catch (error) {
    console.error('[Scheduler] Priority maintenance failed:', error);
  }

  // 1. Run Cover Refresh Scheduler (Daily metadata sync)
  try {
    await runCoverRefreshScheduler();
  } catch (error) {
    console.error('[Scheduler] Cover refresh scheduler failed:', error);
  }

  // 2. Run Deferred Search Scheduler (Background catalog enrichment)
  try {
    await runDeferredSearchScheduler();
    } catch (error) {
      console.error('[Scheduler] Deferred search scheduler failed:', error);
    }

      // 3. Run Notification Digest Scheduler (Grouped updates)
      try {
        await runNotificationDigestScheduler();
      } catch (error) {
        console.error('[Scheduler] Notification digest scheduler failed:', error);
      }

      // 4. Run Safety Monitor Scheduler (Anti-starvation & Health)
      try {
        await runSafetyMonitor();
      } catch (error) {
        console.error('[Scheduler] Safety monitor scheduler failed:', error);
      }

  // 5. Run Sync Source Scheduler (Chapter updates)
  try {
    // Find sources due for check
    const sourcesToUpdate = await prisma.seriesSource.findMany({
      where: {
        OR: [
          { next_check_at: { lte: now } },
          { next_check_at: null }
        ]
      },
      select: {
        id: true,
        sync_priority: true,
      },
        take: 500, // Batch limit
    });

    if (sourcesToUpdate.length === 0) {
      console.log('[Scheduler] No sources due for sync.');
      return;
    }

    console.log(`[Scheduler] Queuing ${sourcesToUpdate.length} sources for sync.`);

    // Group sources by priority for batch updates
    const updatesByPriority: Record<string, string[]> = {
      HOT: [],
      WARM: [],
      COLD: [],
    };

    const jobs = sourcesToUpdate.map(source => {
      const priority = source.sync_priority as SyncPriority;
      if (updatesByPriority[priority]) {
        updatesByPriority[priority].push(source.id);
      } else {
        updatesByPriority.COLD.push(source.id); // Default to COLD
      }

      // Stable jobId (without timestamp) enables BullMQ's built-in deduplication
      // A job with this ID won't be added if it's already in the queue (waiting/active)
      const stableJobId = `sync-${source.id}`;

      return {
        name: `sync-${source.id}`,
        data: { seriesSourceId: source.id },
        opts: {
          jobId: stableJobId,
          priority: priority === 'HOT' ? 1 : priority === 'WARM' ? 2 : 3,
          removeOnComplete: true,
          removeOnFail: { age: 24 * 3600 } // Keep failed jobs for 24h for debugging
        }
      };
    });

    // 6. Batch update next_check_at BEFORE enqueuing to prevent race conditions
    // If enqueuing fails, it will be retried in the next scheduler run (5m later)
    const updatePromises = Object.entries(updatesByPriority)
      .filter(([_, ids]) => ids.length > 0)
      .map(([priority, ids]) => {
        const interval = SYNC_INTERVALS[priority as SyncPriority] || SYNC_INTERVALS.COLD;
        const nextCheck = new Date(now.getTime() + interval);

        return prisma.seriesSource.updateMany({
          where: { id: { in: ids } },
          data: { next_check_at: nextCheck }
        });
      });

    await Promise.all(updatePromises);

    // 7. Bulk add jobs to queue
    await syncSourceQueue.addBulk(jobs);

    console.log(`[Scheduler] Queued ${jobs.length} jobs, updated next_check_at`);
  } catch (error) {
    console.error('[Scheduler] Sync source scheduler failed:', error);
  }
}
