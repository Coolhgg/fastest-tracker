import { checkSourceQueue, isQueueHealthy } from '@/lib/queues';
import { areWorkersOnline } from '@/lib/redis';
import { 
    getDeferredQueryHashes, 
    getDeferredQueryData, 
    removeDeferredSearchQuery, 
    incrementDeferredRetryCount,
    getQueryHeat,
    SEARCH_PRIORITY
  } from '@/lib/search-cache';

import { detectSearchIntent } from '@/lib/search-intent';

const BATCH_SIZE = 10;
const MAX_RETRIES = 5;

/**
 * Off-peak retry worker for deferred search queries.
 * Slowly enriches the catalog by processing queries that were previously skipped.
 */
export async function runDeferredSearchScheduler() {
  console.log('[DeferredSearch] Checking for deferred queries...');

  // 1. Health checks - only run if system has capacity
  const [workersOnline, queueHealthy] = await Promise.all([
    areWorkersOnline(),
    isQueueHealthy(checkSourceQueue, 5000)
  ]);

  if (!workersOnline || !queueHealthy) {
    console.log(`[DeferredSearch] Skipping cycle: workersOnline=${workersOnline}, queueHealthy=${queueHealthy}`);
    return;
  }

  // 2. Fetch a random batch of deferred query hashes
  const hashes = await getDeferredQueryHashes(BATCH_SIZE);
  if (hashes.length === 0) {
    console.log('[DeferredSearch] No deferred queries found.');
    return;
  }

  let resolved = 0;
  let dropped = 0;
  let skipped = 0;

  for (const hash of hashes) {
    try {
      const data = await getDeferredQueryData(hash);
      if (!data) {
        await removeDeferredSearchQuery(hash);
        continue;
      }

      // 3. Safety Check: Retry limit or TTL (TTL handled by Redis setex)
      if (data.retry_count >= MAX_RETRIES) {
        console.log(`[DeferredSearch] [deferred_dropped] query="${data.query}" reason=retry_limit`);
        await removeDeferredSearchQuery(hash);
        dropped++;
        continue;
      }

        // 4. Re-evaluate eligibility (Heat check)
        const heat = await getQueryHeat(data.query);
        
        // If the query was skipped due to heat, it must now be "hot" (unless premium)
        // If it was skipped due to system load, we can retry it regardless of heat (it already passed heat gating)
        const wasEligibleOriginally = data.skip_reason !== 'low_heat';
        const isEligibleNow = heat.count >= 2 || heat.unique_users >= 2 || data.is_premium;

        if (wasEligibleOriginally || isEligibleNow) {
          // Enqueue search with appropriate priority
          const intent = detectSearchIntent(data.query, []);
          const jobId = `deferred_search_${hash}`;
          
          const priority = data.is_premium ? SEARCH_PRIORITY.HIGH : SEARCH_PRIORITY.LOW;

          await checkSourceQueue.add('check-source', {
            query: data.query,
            intent,
            trigger: 'deferred_retry',
            isPremium: data.is_premium
          }, {
            jobId,
            priority,
            removeOnComplete: true,
          });

          console.log(`[DeferredSearch] [deferred_resolved] query="${data.query}" reason=${data.skip_reason} heat=${heat.count} premium=${data.is_premium}`);
          await removeDeferredSearchQuery(hash);
          resolved++;
        } else {

        // Still cold, increment retry and keep in list
        const newCount = await incrementDeferredRetryCount(hash);
        console.log(`[DeferredSearch] query="${data.query}" still cold (heat=${heat.count}). Retry ${newCount}/${MAX_RETRIES}`);
        skipped++;
      }
    } catch (err) {
      console.error(`[DeferredSearch] Error processing hash ${hash}:`, err);
    }
  }

  console.log(`[DeferredSearch] Cycle complete: resolved=${resolved}, dropped=${dropped}, skipped=${skipped}`);
}
