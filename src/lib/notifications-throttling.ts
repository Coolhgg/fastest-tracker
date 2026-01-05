import { redis, REDIS_KEY_PREFIX } from './redis';

const DEDUPE_TTL = 7 * 24 * 60 * 60; // 7 days (increased to prevent duplicate sources)
const USER_DAILY_LIMIT = 50; // Increased for safety-first
const USER_HOURLY_LIMIT = 100;
const USER_DAILY_TTL = 24 * 60 * 60; // 24 hours
const USER_HOURLY_TTL = 60 * 60; // 1 hour
const MANGA_HOURLY_TTL = 60 * 60; // 1 hour

/**
 * Checks if a notification for a specific chapter of a series has already been processed.
 * Prevents multiple sources from triggering separate notifications for the same chapter.
 */
export async function shouldNotifyChapter(seriesId: string, chapterNumber: number): Promise<boolean> {
  const key = `${REDIS_KEY_PREFIX}notify:dedupe:${seriesId}:${chapterNumber}`;
  const result = await redis.set(key, '1', 'EX', DEDUPE_TTL, 'NX');
  return result === 'OK';
}

/**
 * Checks if a user has exceeded their notification limits.
 * Implements:
 * 1. Max notifications per manga per user per hour (1)
 * 2. Max notifications per user per hour (100)
 * 3. Max notifications per user per day (50)
 */
export async function shouldThrottleUser(userId: string, seriesId: string, isPremium = false): Promise<{ throttle: boolean; reason?: string }> {
  const dailyKey = `throttle:user:${userId}:daily`;
  const hourlyKey = `throttle:user:${userId}:hourly`;
  const mangaKey = `throttle:user:${userId}:manga:${seriesId}`;

  // 1. Check Manga Hourly Limit (Only 1 notification per series per hour)
  const mangaLimit = await redis.set(mangaKey, '1', 'EX', MANGA_HOURLY_TTL, 'NX');
  if (mangaLimit !== 'OK') {
    return { throttle: true, reason: 'manga_hourly_limit' };
  }

  // 2. Check Hourly Limit (Abuse Prevention)
  const hourlyCount = await redis.incr(hourlyKey);
  if (hourlyCount === 1) {
    await redis.expire(hourlyKey, USER_HOURLY_TTL);
  }

  if (hourlyCount > USER_HOURLY_LIMIT) {
    return { throttle: true, reason: 'user_hourly_limit' };
  }

  // 3. Check Daily Limit
  const dailyCount = await redis.incr(dailyKey);
  if (dailyCount === 1) {
    await redis.expire(dailyKey, USER_DAILY_TTL);
  }

  // Premium users have higher daily limits
  const effectiveDailyLimit = isPremium ? 500 : USER_DAILY_LIMIT;

  if (dailyCount > effectiveDailyLimit) {
    return { throttle: true, reason: 'user_daily_limit' };
  }

  return { throttle: false };
}
