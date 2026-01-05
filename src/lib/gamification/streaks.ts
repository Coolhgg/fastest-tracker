
import { differenceInDays, isSameDay, subDays } from 'date-fns';

// Maximum streak to prevent integer overflow
const MAX_STREAK = 365 * 100; // 100 years

/**
 * Calculates the new streak count based on current streak and last activity date
 * Includes bounds checking for safety
 */
export function calculateNewStreak(currentStreak: number, lastReadAt: Date | null): number {
  const now = new Date();
  
  // Ensure currentStreak is valid
  const safeStreak = Math.max(0, Math.min(currentStreak || 0, MAX_STREAK));
  
  if (!lastReadAt) {
    return 1;
  }

  // Validate lastReadAt is a valid date
  const lastReadDate = new Date(lastReadAt);
  if (isNaN(lastReadDate.getTime())) {
    return 1;
  }

  // If already read today, streak remains the same
  if (isSameDay(lastReadDate, now)) {
    return Math.max(1, safeStreak);
  }

  // If read yesterday, increment streak
  const yesterday = subDays(now, 1);
  if (isSameDay(lastReadDate, yesterday)) {
    return Math.min(safeStreak + 1, MAX_STREAK);
  }

  // Otherwise, streak reset to 1
  return 1;
}

/**
 * Calculates XP bonus based on current streak
 * e.g., +5 XP per day of streak, capped at 50
 */
export function calculateStreakBonus(streak: number): number {
  // Ensure streak is non-negative
  const safeStreak = Math.max(0, streak);
  return Math.min(safeStreak * 5, 50);
}
