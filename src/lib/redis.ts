import Redis, { RedisOptions } from 'ioredis';

export const REDIS_KEY_PREFIX = 'kenmei:';

/**
 * Determines if Sentinel mode is enabled based on environment variables.
 * Sentinel is ONLY enabled when REDIS_SENTINEL_HOSTS is set.
 */
const isSentinelMode = !!process.env.REDIS_SENTINEL_HOSTS;

/**
 * Parse Sentinel hosts from env var.
 * Format: "host1:port1,host2:port2,host3:port3"
 */
function parseSentinelHosts(): Array<{ host: string; port: number }> {
  const hostsStr = process.env.REDIS_SENTINEL_HOSTS || '';
  if (!hostsStr) return [];
  
  return hostsStr.split(',').map(hostPort => {
    const [host, port] = hostPort.trim().split(':');
    return { host, port: parseInt(port, 10) || 26379 };
  });
}

/**
 * Build Redis connection options based on mode (single-node vs Sentinel).
 * - Single-node: Uses REDIS_URL (default behavior, backward compatible)
 * - Sentinel: Uses REDIS_SENTINEL_* env vars for HA setup
 */
function buildRedisOptions(): RedisOptions {
  const baseOptions: RedisOptions = {
    maxRetriesPerRequest: null, // REQUIRED for BullMQ
    enableOfflineQueue: false,  // Fail fast if disconnected
    connectTimeout: 5000,
    retryStrategy: (times) => {
      if (times > 3) return null; // Stop retrying after 3 attempts to save connections
      return Math.min(times * 500, 2000);
    },
    reconnectOnError: (err) => {
      const targetErrors = ['READONLY', 'ECONNRESET', 'ETIMEDOUT'];
      return targetErrors.some(e => err.message.includes(e));
    },
  };

  if (isSentinelMode) {
    // Sentinel mode configuration
    const sentinels = parseSentinelHosts();
    const masterName = process.env.REDIS_SENTINEL_MASTER_NAME || 'mymaster';
    const sentinelPassword = process.env.REDIS_SENTINEL_PASSWORD || undefined;
    const redisPassword = process.env.REDIS_PASSWORD || undefined;

    console.log('[Redis] Sentinel mode enabled with %d sentinels, master: %s', sentinels.length, masterName);

    return {
      ...baseOptions,
      sentinels,
      name: masterName,
      sentinelPassword,
      password: redisPassword,
      // Sentinel-specific options for HA
      enableReadyCheck: true,
      sentinelRetryStrategy: (times) => {
        if (times > 5) return null;
        return Math.min(times * 1000, 5000);
      },
      // On failover, automatically update to new master
      failoverDetector: true,
    };
  }

  // Single-node mode (default - backward compatible)
  const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
  const parsedUrl = new URL(redisUrl);

  console.log('[Redis] Single-node mode using REDIS_URL');

  return {
    ...baseOptions,
    host: parsedUrl.hostname,
    port: parseInt(parsedUrl.port) || 6379,
    password: parsedUrl.password || undefined,
    username: parsedUrl.username || undefined,
  };
}

/**
 * Connection options for BullMQ (NOT a shared instance).
 * BullMQ will create its own managed connections using these options.
 * Supports both single-node and Sentinel modes.
 */
export const redisConnection: RedisOptions = buildRedisOptions();

/**
 * Singleton pattern for Next.js hot reload protection
 */
const globalForRedis = globalThis as unknown as { redis: Redis | undefined };

function createRedisClient(): Redis {
  const client = new Redis({
    ...redisConnection,
    enableReadyCheck: true,
    lazyConnect: true,
  });

  client.on('error', (err) => {
    if (err.message.includes('ECONNREFUSED') || err.message.includes('ENOTFOUND')) {
      return;
    }
    console.error('[Redis] Unexpected error:', err.message);
  });

  client.on('connect', () => console.log('[Redis] Connection initialized'));
  client.on('close', () => console.log('[Redis] Connection closed'));
  client.on('ready', () => console.log('[Redis] Ready to accept commands'));

  // Sentinel-specific events for debugging
  if (isSentinelMode) {
    client.on('+switch-master', () => {
      console.log('[Redis Sentinel] Master switch detected - reconnecting to new master');
    });
  }

  return client;
}

export const redis = globalForRedis.redis ?? createRedisClient();

if (process.env.NODE_ENV !== 'production') {
  globalForRedis.redis = redis;
}

/**
 * Check if Redis is currently connected and responsive.
 * Uses the actual redis.status which is authoritative.
 */
export function isRedisAvailable(): boolean {
  const status = redis.status;
  return status === 'ready';
}

/**
 * Wait for Redis to be ready (with timeout).
 * Useful for initial connection establishment in serverless environments.
 * Works with both single-node and Sentinel modes.
 */
export async function waitForRedis(timeoutMs: number = 3000): Promise<boolean> {
  const status = redis.status;
  
  // Already ready
  if (status === 'ready') {
    return true;
  }
  
  // Already failed/closed - not going to recover
  if (status === 'end' || status === 'close') {
    console.log('[Redis] waitForRedis: Connection ended/closed, returning false');
    return false;
  }
  
  // Wait for ready event or timeout
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      console.log('[Redis] waitForRedis: Timeout waiting for ready state (status=%s)', redis.status);
      resolve(false);
    }, timeoutMs);
    
    const onReady = () => {
      clearTimeout(timeout);
      redis.off('error', onError);
      resolve(true);
    };
    
    const onError = () => {
      clearTimeout(timeout);
      redis.off('ready', onReady);
      resolve(false);
    };
    
    redis.once('ready', onReady);
    redis.once('error', onError);
  });
}

/**
 * Check if workers are online by checking for a heartbeat key in Redis.
 * Workers should set this key periodically.
 * This function will wait briefly for Redis to connect if needed.
 * Works with both single-node and Sentinel modes.
 */
export async function areWorkersOnline(): Promise<boolean> {
  // Wait for Redis to be ready (up to 3 seconds)
  const redisReady = await waitForRedis(3000);
  
  if (!redisReady) {
    console.log('[Redis] areWorkersOnline: Redis not ready after waiting (status=%s)', redis.status);
    return false;
  }
  
  try {
    const heartbeat = await redis.get(`${REDIS_KEY_PREFIX}workers:heartbeat`);
    
    if (!heartbeat) {
      console.log('[Redis] areWorkersOnline: No heartbeat key found - workers offline');
      return false;
    }
    
    // Heartbeat is valid if it's less than 15 seconds old
    const lastBeat = parseInt(heartbeat, 10);
    const now = Date.now();
    const age = now - lastBeat;
    const isValid = age < 15000; // 15 seconds
    
    console.log('[Redis] areWorkersOnline: Heartbeat age=%dms, isValid=%s', age, isValid);
    
    return isValid;
  } catch (err) {
    console.error('[Redis] Error checking worker heartbeat:', err);
    return false;
  }
}

/**
 * Set worker heartbeat (called by worker process).
 * Sets key with 10 second TTL, called every 5 seconds by workers.
 * Remains functional during Sentinel failover (reconnects automatically).
 */
export async function setWorkerHeartbeat(): Promise<void> {
  try {
    await redis.set(`${REDIS_KEY_PREFIX}workers:heartbeat`, Date.now().toString(), 'EX', 10);
    console.log('[Workers] Heartbeat updated');
  } catch (err) {
    console.error('[Redis] Error setting worker heartbeat:', err);
  }
}

/**
 * Safely disconnects from Redis, ensuring all pending commands are processed.
 */
export async function disconnectRedis(): Promise<void> {
  if (redis.status === 'end') return;
  
  try {
    await redis.quit();
    console.log('[Redis] Disconnected');
  } catch (err) {
    console.error('[Redis] Error during disconnect:', err);
    redis.disconnect(); // Force disconnect if quit fails
  }
}

/**
 * Export mode for diagnostics/logging
 */
export const redisMode = isSentinelMode ? 'sentinel' : 'single-node';
