
export const XP_PER_CHAPTER = 10;
export const XP_SERIES_COMPLETED = 100;
export const XP_DAILY_STREAK_BONUS = 5;

// Maximum XP to prevent integer overflow issues
export const MAX_XP = 999_999_999;

/**
 * Calculates current level based on total XP
 * Formula: level = floor(sqrt(xp / 100)) + 1
 * Level 1: 0-99 XP
 * Level 2: 100-399 XP
 * Level 3: 400-899 XP
 * 
 * Includes bounds checking for safety
 */
export function calculateLevel(xp: number): number {
  // Ensure XP is non-negative and within bounds
  const safeXp = Math.max(0, Math.min(xp, MAX_XP));
  return Math.floor(Math.sqrt(safeXp / 100)) + 1;
}

/**
 * Calculates XP required for a specific level
 */
export function xpForLevel(level: number): number {
  if (level <= 1) return 0;
  // Cap level to prevent overflow
  const safeLevel = Math.min(level, 10000);
  return Math.pow(safeLevel - 1, 2) * 100;
}

/**
 * Calculates progress within the current level (0 to 1)
 */
export function calculateLevelProgress(xp: number): number {
  // Ensure XP is non-negative
  const safeXp = Math.max(0, xp);
  const currentLevel = calculateLevel(safeXp);
  const currentLevelXp = xpForLevel(currentLevel);
  const nextLevelXp = xpForLevel(currentLevel + 1);
  
  const xpInCurrentLevel = safeXp - currentLevelXp;
  const xpNeededForNextLevel = nextLevelXp - currentLevelXp;
  
  // Guard against division by zero
  if (xpNeededForNextLevel <= 0) return 1;
  
  return Math.min(1, xpInCurrentLevel / xpNeededForNextLevel);
}

/**
 * Safely adds XP with overflow protection
 */
export function addXp(currentXp: number, xpToAdd: number): number {
  const newXp = currentXp + xpToAdd;
  return Math.max(0, Math.min(newXp, MAX_XP));
}
