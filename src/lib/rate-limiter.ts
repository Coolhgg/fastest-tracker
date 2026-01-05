import { redis, REDIS_KEY_PREFIX } from './redis';

/**
 * Per-source rate limiting configuration.
 * Each source has different tolerance levels based on their API policies.
 * 
 * Requests per second (rps) - enforced via sliding window
 * Burst size - maximum tokens that can accumulate
 */
export interface SourceRateConfig {
  requestsPerSecond: number;
  burstSize: number;
  cooldownMs: number; // Minimum wait between requests
}

/**
 * Default rate limits per source.
 * Conservative defaults - can be overridden via environment variables.
 * 
 * Format for env override: RATE_LIMIT_<SOURCE>=requestsPerSecond,burstSize,cooldownMs
 * Example: RATE_LIMIT_MANGADEX=5,10,200
 */
const DEFAULT_SOURCE_LIMITS: Record<string, SourceRateConfig> = {
  mangadex: {
    requestsPerSecond: 5,    // MangaDex API is generous
    burstSize: 10,
    cooldownMs: 200,
  },
  mangapark: {
    requestsPerSecond: 2,    // More aggressive scraping protection
    burstSize: 5,
    cooldownMs: 500,
  },
  comick: {
    requestsPerSecond: 3,
    burstSize: 6,
    cooldownMs: 333,
  },
  mangasee: {
    requestsPerSecond: 1,    // Very strict
    burstSize: 3,
    cooldownMs: 1000,
  },
};

// Fallback for unknown sources - very conservative
const DEFAULT_LIMIT: SourceRateConfig = {
  requestsPerSecond: 1,
  burstSize: 2,
  cooldownMs: 1000,
};

/**
 * Get rate limit config for a source.
 * Checks environment variable override first, then falls back to defaults.
 */
export function getSourceRateConfig(sourceName: string): SourceRateConfig {
  const normalized = sourceName.toLowerCase();
  
  // Check for env override: RATE_LIMIT_MANGADEX=5,10,200
  const envKey = `RATE_LIMIT_${normalized.toUpperCase()}`;
  const envValue = process.env[envKey];
  
  if (envValue) {
    const parts = envValue.split(',').map(p => parseInt(p.trim(), 10));
    if (parts.length === 3 && parts.every(p => !isNaN(p) && p > 0)) {
      return {
        requestsPerSecond: parts[0],
        burstSize: parts[1],
        cooldownMs: parts[2],
      };
    }
    console.warn(`[RateLimiter] Invalid env override for ${envKey}: ${envValue}, using defaults`);
  }
  
  return DEFAULT_SOURCE_LIMITS[normalized] || DEFAULT_LIMIT;
}

/**
 * Token bucket rate limiter using Redis.
 * 
 * Each source has its own bucket, stored in Redis as:
 * - kenmei:ratelimit:<source>:tokens (current token count)
 * - kenmei:ratelimit:<source>:last_refill (last refill timestamp)
 * 
 * This approach:
 * 1. Survives worker restarts (stored in Redis)
 * 2. Works across multiple worker instances
 * 3. Allows burst traffic while maintaining average rate
 * 4. Per-source isolation - one source failure doesn't affect others
 */
export class SourceRateLimiter {
  private readonly keyPrefix: string;
  
  constructor() {
    this.keyPrefix = `${REDIS_KEY_PREFIX}ratelimit:`;
  }
  
  /**
   * Acquire a token for the given source.
   * Returns immediately if token available, otherwise waits.
   * 
   * @param sourceName - The source to rate limit (e.g., 'mangadex')
   * @param maxWaitMs - Maximum time to wait for a token (default: 30s)
   * @returns true if token acquired, false if timed out
   */
  async acquireToken(sourceName: string, maxWaitMs: number = 30000): Promise<boolean> {
    const normalized = sourceName.toLowerCase();
    const config = getSourceRateConfig(normalized);
    const tokensKey = `${this.keyPrefix}${normalized}:tokens`;
    const lastRefillKey = `${this.keyPrefix}${normalized}:last_refill`;
    
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWaitMs) {
      // Atomic operation using Redis transaction
      const result = await this.tryAcquireToken(
        tokensKey,
        lastRefillKey,
        config
      );
      
      if (result.acquired) {
        // Enforce minimum cooldown between requests
        if (config.cooldownMs > 0) {
          await this.sleep(config.cooldownMs);
        }
        return true;
      }
      
      // Wait before retry - use the suggested wait time from token bucket
      const waitTime = Math.min(result.waitMs, maxWaitMs - (Date.now() - startTime));
      if (waitTime > 0) {
        await this.sleep(waitTime);
      }
    }
    
    console.warn(`[RateLimiter] Timeout waiting for token for ${sourceName}`);
    return false;
  }
  
  /**
   * Non-blocking check if a token is available.
   * Useful for backpressure detection.
   */
  async hasAvailableToken(sourceName: string): Promise<boolean> {
    const normalized = sourceName.toLowerCase();
    const config = getSourceRateConfig(normalized);
    const tokensKey = `${this.keyPrefix}${normalized}:tokens`;
    const lastRefillKey = `${this.keyPrefix}${normalized}:last_refill`;
    
    const result = await this.getTokenState(tokensKey, lastRefillKey, config);
    return result.tokens >= 1;
  }
  
  /**
   * Get current rate limit status for a source.
   * Useful for monitoring/debugging.
   */
  async getStatus(sourceName: string): Promise<{
    tokens: number;
    maxTokens: number;
    requestsPerSecond: number;
    lastRefillAt: Date | null;
  }> {
    const normalized = sourceName.toLowerCase();
    const config = getSourceRateConfig(normalized);
    const tokensKey = `${this.keyPrefix}${normalized}:tokens`;
    const lastRefillKey = `${this.keyPrefix}${normalized}:last_refill`;
    
    const state = await this.getTokenState(tokensKey, lastRefillKey, config);
    
    return {
      tokens: Math.floor(state.tokens),
      maxTokens: config.burstSize,
      requestsPerSecond: config.requestsPerSecond,
      lastRefillAt: state.lastRefillAt,
    };
  }
  
  /**
   * Atomic token acquisition using Redis Lua script.
   * This ensures correctness even with multiple workers.
   */
  private async tryAcquireToken(
    tokensKey: string,
    lastRefillKey: string,
    config: SourceRateConfig
  ): Promise<{ acquired: boolean; waitMs: number }> {
    const now = Date.now();
    
    // Lua script for atomic token bucket operation
    // Returns: [acquired (0/1), waitMs]
    const script = `
      local tokensKey = KEYS[1]
      local lastRefillKey = KEYS[2]
      local now = tonumber(ARGV[1])
      local rps = tonumber(ARGV[2])
      local burstSize = tonumber(ARGV[3])
      
      -- Get current state
      local tokens = tonumber(redis.call('GET', tokensKey) or burstSize)
      local lastRefill = tonumber(redis.call('GET', lastRefillKey) or now)
      
      -- Calculate refill
      local elapsed = (now - lastRefill) / 1000  -- seconds
      local refillAmount = elapsed * rps
      tokens = math.min(burstSize, tokens + refillAmount)
      
      -- Try to acquire
      if tokens >= 1 then
        tokens = tokens - 1
        redis.call('SET', tokensKey, tokens, 'EX', 3600)
        redis.call('SET', lastRefillKey, now, 'EX', 3600)
        return {1, 0}
      else
        -- Calculate wait time until 1 token available
        local deficit = 1 - tokens
        local waitMs = math.ceil((deficit / rps) * 1000)
        -- Update refill timestamp even if no acquisition
        redis.call('SET', tokensKey, tokens, 'EX', 3600)
        redis.call('SET', lastRefillKey, now, 'EX', 3600)
        return {0, waitMs}
      end
    `;
    
    const result = await redis.eval(
      script,
      2,
      tokensKey,
      lastRefillKey,
      now.toString(),
      config.requestsPerSecond.toString(),
      config.burstSize.toString()
    ) as [number, number];
    
    return {
      acquired: result[0] === 1,
      waitMs: result[1],
    };
  }
  
  /**
   * Get current token state without modifying.
   */
  private async getTokenState(
    tokensKey: string,
    lastRefillKey: string,
    config: SourceRateConfig
  ): Promise<{ tokens: number; lastRefillAt: Date | null }> {
    const [tokensStr, lastRefillStr] = await Promise.all([
      redis.get(tokensKey),
      redis.get(lastRefillKey),
    ]);
    
    const now = Date.now();
    let tokens = tokensStr ? parseFloat(tokensStr) : config.burstSize;
    const lastRefill = lastRefillStr ? parseInt(lastRefillStr, 10) : now;
    
    // Calculate current tokens after refill
    const elapsed = (now - lastRefill) / 1000;
    const refillAmount = elapsed * config.requestsPerSecond;
    tokens = Math.min(config.burstSize, tokens + refillAmount);
    
    return {
      tokens,
      lastRefillAt: lastRefillStr ? new Date(lastRefill) : null,
    };
  }
  
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Singleton instance
const globalForRateLimiter = globalThis as unknown as { 
  sourceRateLimiter: SourceRateLimiter | undefined 
};

export const sourceRateLimiter = globalForRateLimiter.sourceRateLimiter ?? new SourceRateLimiter();

if (process.env.NODE_ENV !== 'production') {
  globalForRateLimiter.sourceRateLimiter = sourceRateLimiter;
}

/**
 * Rate limit table for documentation:
 * 
 * | Source     | Requests/sec | Burst | Cooldown | Notes                    |
 * |------------|--------------|-------|----------|--------------------------|
 * | MangaDex   | 5            | 10    | 200ms    | Official API, generous   |
 * | MangaPark  | 2            | 5     | 500ms    | Web scraping, be polite  |
 * | Comick     | 3            | 6     | 333ms    | API available            |
 * | MangaSee   | 1            | 3     | 1000ms   | Very strict, Cloudflare  |
 * | Default    | 1            | 2     | 1000ms   | Unknown sources          |
 * 
 * Override via env: RATE_LIMIT_<SOURCE>=requestsPerSecond,burstSize,cooldownMs
 */
