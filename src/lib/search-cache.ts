import { redis, REDIS_KEY_PREFIX, waitForRedis } from './redis';

const SEARCH_CACHE_PREFIX = `${REDIS_KEY_PREFIX}search:cache:`;
const SEARCH_PENDING_PREFIX = `${REDIS_KEY_PREFIX}search:pending:`;
const SEARCH_STATS_PREFIX = `${REDIS_KEY_PREFIX}search:stats:`;
const SEARCH_HEAT_PREFIX = `${REDIS_KEY_PREFIX}search:heat:`;
const SEARCH_DEFERRED_PREFIX = `${REDIS_KEY_PREFIX}search:deferred:`;
const SEARCH_DEFERRED_ZSET = `${REDIS_KEY_PREFIX}search:deferred_zset`;
const PREMIUM_QUOTA_PREFIX = `${REDIS_KEY_PREFIX}premium:quota:`;
const PREMIUM_CONCURRENCY_PREFIX = `${REDIS_KEY_PREFIX}premium:concurrency:`;

export const SEARCH_PRIORITY = {
  CRITICAL: 1,  // Premium Direct Search
  HIGH: 5,      // Premium Deferred/Updates
  STANDARD: 10, // Free Direct Search
  LOW: 20,      // Free Deferred/Background
};

const PREMIUM_WEIGHT = 0;
const FREE_WEIGHT = 1e12; // Shifts free users 1 year into future

export interface CachedSearchResult {
  results: any[];
  total?: number;
  has_more: boolean;
  next_cursor: string | null;
  cached_at: number;
  source: 'cache';
}

export interface SearchCacheConfig {
  ttlSeconds: number;
  maxPendingWaitMs: number;
  enableDeduplication: boolean;
}

const DEFAULT_CONFIG: SearchCacheConfig = {
  ttlSeconds: 3600,
  maxPendingWaitMs: 5000,
  enableDeduplication: true,
};

function normalizeQuery(query: string): string {
  return query.toLowerCase().trim().replace(/\s+/g, ' ');
}

function buildCacheKey(query: string, filters: Record<string, any>): string {
  const normalizedQuery = normalizeQuery(query);
  const filterHash = Object.entries(filters)
    .filter(([k, v]) => v !== undefined && v !== null && k !== 'cursor')
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}:${JSON.stringify(v)}`)
    .join('|');
  
  const keyBase = `${normalizedQuery}::${filterHash}`;
  return Buffer.from(keyBase).toString('base64').slice(0, 64);
}

export async function getCachedSearchResult(
  query: string,
  filters: Record<string, any>
): Promise<CachedSearchResult | null> {
  const ready = await waitForRedis(1000);
  if (!ready) return null;

  try {
    const cacheKey = `${SEARCH_CACHE_PREFIX}${buildCacheKey(query, filters)}`;
    const cached = await redis.get(cacheKey);
    
    if (cached) {
      await redis.hincrby(`${SEARCH_STATS_PREFIX}global`, 'hits', 1);
      return JSON.parse(cached);
    }
    
    await redis.hincrby(`${SEARCH_STATS_PREFIX}global`, 'misses', 1);
    return null;
  } catch (err) {
    console.error('[SearchCache] getCached error:', err);
    return null;
  }
}

export async function setCachedSearchResult(
  query: string,
  filters: Record<string, any>,
  result: Omit<CachedSearchResult, 'cached_at' | 'source'>,
  config: Partial<SearchCacheConfig> = {}
): Promise<void> {
  const ready = await waitForRedis(1000);
  if (!ready) return;

  const { ttlSeconds } = { ...DEFAULT_CONFIG, ...config };

  try {
    const cacheKey = `${SEARCH_CACHE_PREFIX}${buildCacheKey(query, filters)}`;
    const cacheData: CachedSearchResult = {
      ...result,
      cached_at: Date.now(),
      source: 'cache',
    };
    
    await redis.setex(cacheKey, ttlSeconds, JSON.stringify(cacheData));
  } catch (err) {
    console.error('[SearchCache] setCache error:', err);
  }
}

export async function checkPendingSearch(
  query: string,
  filters: Record<string, any>
): Promise<string | null> {
  const ready = await waitForRedis(500);
  if (!ready) return null;

  try {
    const pendingKey = `${SEARCH_PENDING_PREFIX}${buildCacheKey(query, filters)}`;
    return await redis.get(pendingKey);
  } catch (err) {
    console.error('[SearchCache] checkPending error:', err);
    return null;
  }
}

export async function markSearchPending(
  query: string,
  filters: Record<string, any>,
  requestId: string
): Promise<boolean> {
  const ready = await waitForRedis(500);
  if (!ready) return false;

  try {
    const pendingKey = `${SEARCH_PENDING_PREFIX}${buildCacheKey(query, filters)}`;
    const result = await redis.set(pendingKey, requestId, 'EX', 30, 'NX');
    return result === 'OK';
  } catch (err) {
    console.error('[SearchCache] markPending error:', err);
    return false;
  }
}

export async function clearPendingSearch(
  query: string,
  filters: Record<string, any>
): Promise<void> {
  const ready = await waitForRedis(500);
  if (!ready) return;

  try {
    const pendingKey = `${SEARCH_PENDING_PREFIX}${buildCacheKey(query, filters)}`;
    await redis.del(pendingKey);
  } catch (err) {
    console.error('[SearchCache] clearPending error:', err);
  }
}

export async function waitForPendingSearch(
  query: string,
  filters: Record<string, any>,
  config: Partial<SearchCacheConfig> = {}
): Promise<CachedSearchResult | null> {
  const { maxPendingWaitMs } = { ...DEFAULT_CONFIG, ...config };
  const startTime = Date.now();
  const pollInterval = 100;

  while (Date.now() - startTime < maxPendingWaitMs) {
    const cached = await getCachedSearchResult(query, filters);
    if (cached) {
      await redis.hincrby(`${SEARCH_STATS_PREFIX}global`, 'dedup_saves', 1);
      return cached;
    }

    const stillPending = await checkPendingSearch(query, filters);
    if (!stillPending) {
      return await getCachedSearchResult(query, filters);
    }

    await new Promise(resolve => setTimeout(resolve, pollInterval));
  }

  return null;
}

export interface ExternalSearchDedup {
  shouldProceed: boolean;
  existingJobId: string | null;
}

export async function checkExternalSearchDedup(
  query: string
): Promise<ExternalSearchDedup> {
  const ready = await waitForRedis(500);
  if (!ready) return { shouldProceed: true, existingJobId: null };

  try {
    const normalizedQuery = normalizeQuery(query);
    const dedupKey = `${REDIS_KEY_PREFIX}external:pending:${Buffer.from(normalizedQuery).toString('base64').slice(0, 32)}`;
    
    const existingJobId = await redis.get(dedupKey);
    if (existingJobId) {
      await redis.hincrby(`${SEARCH_STATS_PREFIX}global`, 'external_dedup_saves', 1);
      return { shouldProceed: false, existingJobId };
    }
    
    return { shouldProceed: true, existingJobId: null };
  } catch (err) {
    console.error('[SearchCache] checkExternalDedup error:', err);
    return { shouldProceed: true, existingJobId: null };
  }
}

export async function markExternalSearchPending(
  query: string,
  jobId: string,
  ttlSeconds: number = 60
): Promise<void> {
  const ready = await waitForRedis(500);
  if (!ready) return;

  try {
    const normalizedQuery = normalizeQuery(query);
    const dedupKey = `${REDIS_KEY_PREFIX}external:pending:${Buffer.from(normalizedQuery).toString('base64').slice(0, 32)}`;
    await redis.setex(dedupKey, ttlSeconds, jobId);
  } catch (err) {
    console.error('[SearchCache] markExternalPending error:', err);
  }
}

export async function getSearchCacheStats(): Promise<{
  hits: number;
  misses: number;
  hitRate: number;
  dedupSaves: number;
  externalDedupSaves: number;
}> {
  const ready = await waitForRedis(500);
  if (!ready) {
    return { hits: 0, misses: 0, hitRate: 0, dedupSaves: 0, externalDedupSaves: 0 };
  }

  try {
    const stats = await redis.hgetall(`${SEARCH_STATS_PREFIX}global`);
    const hits = parseInt(stats.hits || '0', 10);
    const misses = parseInt(stats.misses || '0', 10);
    const dedupSaves = parseInt(stats.dedup_saves || '0', 10);
    const externalDedupSaves = parseInt(stats.external_dedup_saves || '0', 10);
    const total = hits + misses;
    
    return {
      hits,
      misses,
      hitRate: total > 0 ? (hits / total) * 100 : 0,
      dedupSaves,
      externalDedupSaves,
    };
  } catch (err) {
    console.error('[SearchCache] getStats error:', err);
    return { hits: 0, misses: 0, hitRate: 0, dedupSaves: 0, externalDedupSaves: 0 };
  }
}

export async function invalidateSearchCache(pattern?: string): Promise<number> {
  const ready = await waitForRedis(1000);
  if (!ready) return 0;

  try {
    const searchPattern = pattern 
      ? `${SEARCH_CACHE_PREFIX}*${pattern}*`
      : `${SEARCH_CACHE_PREFIX}*`;
    
    let cursor = '0';
    let deletedCount = 0;
    
    do {
      const [nextCursor, keys] = await redis.scan(cursor, 'MATCH', searchPattern, 'COUNT', 100);
      cursor = nextCursor;
      
      if (keys.length > 0) {
        await redis.del(...keys);
        deletedCount += keys.length;
      }
    } while (cursor !== '0');
    
    return deletedCount;
  } catch (err) {
    console.error('[SearchCache] invalidate error:', err);
    return 0;
  }
}

export interface QueryHeat {
  count: number;
  unique_users: number;
  first_seen: number;
  last_seen: number;
}

/**
 * Track search intent and heat for a query.
 * Normalizes query and updates counts/timestamps in Redis.
 */
export async function updateQueryHeat(query: string, userId?: string): Promise<void> {
  const ready = await waitForRedis(500);
  if (!ready) return;

  try {
    const normalized = normalizeQuery(query);
    const hash = Buffer.from(normalized).toString('base64').slice(0, 32);
    const heatKey = `${SEARCH_HEAT_PREFIX}${hash}`;
    const usersKey = `${heatKey}:users`;
    
    const now = Date.now();
    const multi = redis.multi();
    
    multi.hincrby(heatKey, 'count', 1);
    multi.hsetnx(heatKey, 'first_seen', now.toString());
    multi.hset(heatKey, 'last_seen', now.toString());
    
    if (userId) {
      multi.sadd(usersKey, userId);
      multi.expire(usersKey, 86400);
    }
    
    multi.expire(heatKey, 86400);
    await multi.exec();
  } catch (err) {
    console.error('[SearchCache] updateQueryHeat error:', err);
  }
}

/**
 * Get current heat stats for a query.
 */
export async function getQueryHeat(query: string): Promise<QueryHeat> {
  const ready = await waitForRedis(500);
  if (!ready) return { count: 0, unique_users: 0, first_seen: 0, last_seen: 0 };

  try {
    const normalized = normalizeQuery(query);
    const hash = Buffer.from(normalized).toString('base64').slice(0, 32);
    const heatKey = `${SEARCH_HEAT_PREFIX}${hash}`;
    const usersKey = `${heatKey}:users`;
    
    const [stats, unique_users] = await Promise.all([
      redis.hgetall(heatKey),
      redis.scard(usersKey)
    ]);
    
    return {
      count: parseInt(stats.count || '0', 10),
      unique_users: unique_users || 0,
      first_seen: parseInt(stats.first_seen || '0', 10),
      last_seen: parseInt(stats.last_seen || '0', 10)
    };
  } catch (err) {
    console.error('[SearchCache] getQueryHeat error:', err);
    return { count: 0, unique_users: 0, first_seen: 0, last_seen: 0 };
  }
}

export type SkipReason = 'queue_unhealthy' | 'low_heat' | 'workers_offline';

export interface DeferredQuery {
  query: string;
  first_skipped_at: number;
  skip_reason: SkipReason;
  retry_count: number;
  is_premium?: boolean;
}

/**
 * Store a query for deferred external search processing.
 */
export async function deferSearchQuery(
  query: string, 
  reason: SkipReason, 
  isPremium: boolean = false
): Promise<void> {
  const ready = await waitForRedis(500);
  if (!ready) return;

  try {
    const normalized = normalizeQuery(query);
    const hash = Buffer.from(normalized).toString('base64').slice(0, 32);
    const deferredKey = `${SEARCH_DEFERRED_PREFIX}${hash}`;
    
    const setSize = await redis.zcard(SEARCH_DEFERRED_ZSET);
    const MAX_DEFERRED_SIZE = 10000;
    
    const existing = await redis.get(deferredKey);
    let data: DeferredQuery;

    if (existing) {
      const parsed = JSON.parse(existing);
      data = {
        ...parsed,
        skip_reason: reason,
        is_premium: isPremium || parsed.is_premium
      };
    } else {
      if (setSize >= MAX_DEFERRED_SIZE) {
        console.warn(`[Search Defer] Set size limit reached (${setSize}). Skipping query="${normalized}"`);
        return;
      }
      data = {
        query: normalized,
        first_skipped_at: Date.now(),
        skip_reason: reason,
        retry_count: 0,
        is_premium: isPremium
      };
    }

    // Score = Weight + Timestamp
    const weight = data.is_premium ? PREMIUM_WEIGHT : FREE_WEIGHT;
    const score = weight + Date.now();

    await redis.setex(deferredKey, 604800, JSON.stringify(data)); // 7 days
    await redis.zadd(SEARCH_DEFERRED_ZSET, score, hash);
    
    console.log(`[Search Defer] Enqueued query="${normalized}" reason=${reason} premium=${data.is_premium}`);
  } catch (err) {
    console.error('[SearchCache] deferSearchQuery error:', err);
  }
}

/**
 * Get a batch of deferred query hashes.
 * Implements fairness: if premium backlog is huge, still picks some free jobs.
 */
export async function getDeferredQueryHashes(limit: number = 10): Promise<string[]> {
  const ready = await waitForRedis(500);
  if (!ready) return [];

  try {
    // 1. Get potential candidates from top of ZSET
    const hashes = await redis.zrange(SEARCH_DEFERRED_ZSET, 0, limit * 2);
    if (!hashes || hashes.length === 0) return [];

    const validHashes: string[] = [];
    const premiumHashes: string[] = [];
    const freeHashes: string[] = [];

    // 2. Filter and categorize
    for (const hash of hashes) {
      const data = await getDeferredQueryData(hash);
      if (data) {
        if (data.is_premium) premiumHashes.push(hash);
        else freeHashes.push(hash);
      } else {
        // Cleanup orphan
        await redis.zrem(SEARCH_DEFERRED_ZSET, hash);
      }
    }

    // 3. Apply fairness rule: 8 Premium / 2 Free if available
    const premiumLimit = Math.floor(limit * 0.8);
    const freeLimit = limit - premiumLimit;

    const result = [
      ...premiumHashes.slice(0, premiumLimit),
      ...freeHashes.slice(0, limit - Math.min(premiumLimit, premiumHashes.length))
    ].slice(0, limit);

    return result;
  } catch (err) {
    console.error('[SearchCache] getDeferredQueryHashes error:', err);
    return [];
  }
}

/**
 * Get deferred query data by hash.
 */
export async function getDeferredQueryData(hash: string): Promise<DeferredQuery | null> {
  const ready = await waitForRedis(500);
  if (!ready) return null;

  try {
    const data = await redis.get(`${SEARCH_DEFERRED_PREFIX}${hash}`);
    return data ? JSON.parse(data) : null;
  } catch (err) {
    console.error('[SearchCache] getDeferredQueryData error:', err);
    return null;
  }
}

/**
 * Remove a query from deferred processing.
 */
export async function removeDeferredSearchQuery(hash: string): Promise<void> {
  const ready = await waitForRedis(500);
  if (!ready) return;

  try {
    await redis.del(`${SEARCH_DEFERRED_PREFIX}${hash}`);
    await redis.zrem(SEARCH_DEFERRED_ZSET, hash);
  } catch (err) {
    console.error('[SearchCache] removeDeferredSearchQuery error:', err);
  }
}

/**
 * Increment retry count for a deferred query.
 */
export async function incrementDeferredRetryCount(hash: string): Promise<number> {
  const ready = await waitForRedis(500);
  if (!ready) return 0;

  try {
    const deferredKey = `${SEARCH_DEFERRED_PREFIX}${hash}`;
    const existing = await redis.get(deferredKey);
    if (!existing) return 0;

    const data: DeferredQuery = JSON.parse(existing);
    data.retry_count += 1;
    
    await redis.set(deferredKey, JSON.stringify(data), 'KEEPTTL');
    return data.retry_count;
  } catch (err) {
    console.error('[SearchCache] incrementDeferredRetryCount error:', err);
    return 0;
  }
}

/**
 * Premium Quota Management (50/day)
 */
export async function getPremiumQuota(userId: string): Promise<number> {
  const key = `${PREMIUM_QUOTA_PREFIX}${userId}`;
  const val = await redis.get(key);
  return val ? parseInt(val, 10) : 0;
}

export async function incrementPremiumQuota(userId: string): Promise<number> {
  const key = `${PREMIUM_QUOTA_PREFIX}${userId}`;
  const count = await redis.incr(key);
  if (count === 1) {
    await redis.expire(key, 86400); // 24 hours
  }
  return count;
}

/**
 * Premium Concurrency Management (Max 2)
 */
export async function getPremiumConcurrency(userId: string): Promise<number> {
  const key = `${PREMIUM_CONCURRENCY_PREFIX}${userId}`;
  const val = await redis.get(key);
  return val ? parseInt(val, 10) : 0;
}

export async function incrementPremiumConcurrency(userId: string): Promise<number> {
  const key = `${PREMIUM_CONCURRENCY_PREFIX}${userId}`;
  const count = await redis.incr(key);
  // Add TTL to prevent orphaned keys if worker crashes and doesn't decrement
  if (count === 1) {
    await redis.expire(key, 300); // 5 minutes is plenty for a search job
  }
  return count;
}

export async function decrementPremiumConcurrency(userId: string): Promise<number> {
  const key = `${PREMIUM_CONCURRENCY_PREFIX}${userId}`;
  const val = await redis.decr(key);
  if (val <= 0) await redis.del(key);
  return val;
}
