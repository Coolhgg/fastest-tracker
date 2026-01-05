/**
 * Bug Bounty January 2026 - Comprehensive Integration Tests
 * Tests security, edge cases, performance, and error handling
 */

import {
  sanitizeInput,
  escapeILikePattern,
  validateUUID,
  checkRateLimit,
  clearRateLimit,
  ApiError,
  toTitleCase,
  sanitizeFilterArray,
  checkAuthRateLimit,
  validateEmail,
  validateUsername,
  htmlEncode,
} from '@/lib/api-utils';

import {
  calculateLevel,
  calculateLevelProgress,
  xpForLevel,
  addXp,
  MAX_XP,
} from '@/lib/gamification/xp';

import {
  calculateNewStreak,
  calculateStreakBonus,
} from '@/lib/gamification/streaks';

import {
  selectBestSource,
  type ChapterSource,
  type SeriesSourcePreference,
} from '@/lib/source-utils';

import {
  isInternalIP,
  isWhitelistedDomain,
  ALLOWED_CONTENT_TYPES,
} from '@/lib/constants/image-whitelist';

describe('Bug Bounty January 2026 - Integration Tests', () => {
  // ============================================
  // SECURITY TESTS
  // ============================================
  describe('Security - Input Sanitization', () => {
    it('removes HTML script tags', () => {
      expect(sanitizeInput('<script>alert("xss")</script>')).toBe('alert("xss")');
    });

    it('removes HTML img tags with onerror', () => {
      expect(sanitizeInput('<img src=x onerror=alert(1)>')).toBe('');
    });

    it('removes javascript: protocol', () => {
      expect(sanitizeInput('javascript:alert(1)')).toBe('alert(1)');
      expect(sanitizeInput('JAVASCRIPT:alert(1)')).toBe('alert(1)');
    });

    it('removes data: protocol', () => {
      expect(sanitizeInput('data:text/html,<script>alert(1)</script>')).toBe('text/html,alert(1)');
    });

    it('removes event handlers', () => {
      expect(sanitizeInput('test onclick=alert(1)')).not.toContain('onclick');
      expect(sanitizeInput('onmouseover=evil()')).not.toContain('onmouseover');
    });

    it('removes encoded HTML entities', () => {
      expect(sanitizeInput('&#x3C;script&#x3E;')).not.toContain('<');
    });

    it('respects maxLength parameter', () => {
      const longString = 'a'.repeat(1000);
      expect(sanitizeInput(longString, 100).length).toBe(100);
    });

    it('handles unicode correctly', () => {
      expect(sanitizeInput('テスト漫画 🎉')).toBe('テスト漫画 🎉');
    });

    it('trims whitespace', () => {
      expect(sanitizeInput('  hello world  ')).toBe('hello world');
    });
  });

  describe('Security - SQL Injection Prevention', () => {
    it('escapes percent signs in ILIKE patterns', () => {
      expect(escapeILikePattern('100%')).toBe('100\\%');
    });

    it('escapes underscores in ILIKE patterns', () => {
      expect(escapeILikePattern('test_value')).toBe('test\\_value');
    });

    it('escapes backslashes in ILIKE patterns', () => {
      expect(escapeILikePattern('path\\to\\file')).toBe('path\\\\to\\\\file');
    });

    it('handles combined special characters', () => {
      expect(escapeILikePattern('50%_off\\')).toBe('50\\%\\_off\\\\');
    });
  });

  describe('Security - UUID Validation', () => {
    it('accepts valid UUIDs', () => {
      expect(() => validateUUID('550e8400-e29b-41d4-a716-446655440000')).not.toThrow();
      expect(() => validateUUID('123e4567-e89b-12d3-a456-426614174000')).not.toThrow();
    });

    it('rejects invalid UUIDs', () => {
      expect(() => validateUUID('invalid')).toThrow(ApiError);
      expect(() => validateUUID('')).toThrow(ApiError);
      expect(() => validateUUID('550e8400-e29b-41d4-a716')).toThrow(ApiError);
    });

    it('rejects SQL injection attempts', () => {
      expect(() => validateUUID("'; DROP TABLE users;--")).toThrow(ApiError);
    });
  });

  describe('Security - Rate Limiting', () => {
    beforeEach(() => {
      clearRateLimit('test-key');
    });

    it('allows requests within limit', () => {
      for (let i = 0; i < 5; i++) {
        expect(checkRateLimit('test-key', 5, 60000)).toBe(true);
      }
    });

    it('blocks requests exceeding limit', () => {
      for (let i = 0; i < 5; i++) {
        checkRateLimit('test-key', 5, 60000);
      }
      expect(checkRateLimit('test-key', 5, 60000)).toBe(false);
    });

    it('tracks different keys separately', () => {
      for (let i = 0; i < 5; i++) {
        checkRateLimit('key-a', 5, 60000);
      }
      expect(checkRateLimit('key-a', 5, 60000)).toBe(false);
      expect(checkRateLimit('key-b', 5, 60000)).toBe(true);
    });

    it('auth rate limit is stricter', () => {
      // Auth rate limit: 5/min
      for (let i = 0; i < 5; i++) {
        expect(checkAuthRateLimit('test-ip')).toBe(true);
      }
      expect(checkAuthRateLimit('test-ip')).toBe(false);
    });
  });

  describe('Security - SSRF Protection', () => {
    it('blocks localhost', () => {
      expect(isInternalIP('localhost')).toBe(true);
      expect(isInternalIP('127.0.0.1')).toBe(true);
      expect(isInternalIP('::1')).toBe(true);
    });

    it('blocks private IPv4 ranges', () => {
      expect(isInternalIP('10.0.0.1')).toBe(true);
      expect(isInternalIP('172.16.0.1')).toBe(true);
      expect(isInternalIP('192.168.1.1')).toBe(true);
    });

    it('blocks cloud metadata IPs', () => {
      expect(isInternalIP('169.254.169.254')).toBe(true);
      expect(isInternalIP('169.254.170.2')).toBe(true);
    });

    it('blocks IPv6 mapped IPv4', () => {
      expect(isInternalIP('::ffff:127.0.0.1')).toBe(true);
      expect(isInternalIP('::ffff:10.0.0.1')).toBe(true);
    });

    it('allows public IPs', () => {
      expect(isInternalIP('8.8.8.8')).toBe(false);
      expect(isInternalIP('1.1.1.1')).toBe(false);
    });
  });

  describe('Security - Domain Whitelist', () => {
    it('allows whitelisted domains', () => {
      expect(isWhitelistedDomain('https://cdn.mangadex.org/covers/123.jpg')).toBe(true);
      expect(isWhitelistedDomain('https://uploads.mangadex.org/data/abc.png')).toBe(true);
    });

    it('blocks non-whitelisted domains', () => {
      expect(isWhitelistedDomain('https://evil.com/image.jpg')).toBe(false);
      expect(isWhitelistedDomain('https://attacker.com/malware.js')).toBe(false);
    });

    it('handles invalid URLs', () => {
      expect(isWhitelistedDomain('not-a-url')).toBe(false);
      expect(isWhitelistedDomain('')).toBe(false);
    });
  });

  describe('Security - XSS Prevention', () => {
    it('HTML encodes special characters', () => {
      expect(htmlEncode('<script>')).toBe('&lt;script&gt;');
      expect(htmlEncode('"test"')).toBe('&quot;test&quot;');
      expect(htmlEncode("'test'")).toBe('&#x27;test&#x27;');
    });

    it('SVG is not in allowed content types', () => {
      expect(ALLOWED_CONTENT_TYPES).not.toContain('image/svg+xml');
    });
  });

  // ============================================
  // EDGE CASE TESTS
  // ============================================
  describe('Edge Cases - XP and Level Calculation', () => {
    it('calculates level correctly', () => {
      expect(calculateLevel(0)).toBe(1);
      expect(calculateLevel(99)).toBe(1);
      expect(calculateLevel(100)).toBe(2);
      expect(calculateLevel(400)).toBe(3);
    });

    it('handles negative XP', () => {
      expect(calculateLevel(-100)).toBe(1);
      expect(calculateLevel(-1)).toBe(1);
    });

    it('caps XP at MAX_XP', () => {
      const hugeXp = Number.MAX_SAFE_INTEGER;
      const level = calculateLevel(hugeXp);
      expect(Number.isFinite(level)).toBe(true);
      expect(level).toBeLessThan(10001);
    });

    it('safely adds XP with overflow protection', () => {
      expect(addXp(100, 50)).toBe(150);
      expect(addXp(MAX_XP, 1000)).toBe(MAX_XP);
      expect(addXp(100, -200)).toBe(0);
    });

    it('level progress never exceeds 1', () => {
      expect(calculateLevelProgress(MAX_XP)).toBeLessThanOrEqual(1);
    });
  });

  describe('Edge Cases - Streak Calculation', () => {
    it('returns 1 for null lastReadAt', () => {
      expect(calculateNewStreak(5, null)).toBe(1);
    });

    it('handles invalid dates', () => {
      expect(calculateNewStreak(5, new Date('invalid'))).toBe(1);
    });

    it('streak bonus is capped at 50', () => {
      expect(calculateStreakBonus(100)).toBe(50);
      expect(calculateStreakBonus(1000)).toBe(50);
    });

    it('streak bonus handles negative streak', () => {
      expect(calculateStreakBonus(-5)).toBe(0);
    });
  });

  describe('Edge Cases - Source Selection', () => {
    const mockSources: ChapterSource[] = [
      { id: '1', source_name: 'MangaDex', source_id: 'md1', chapter_url: 'https://mangadex.org/1', published_at: '2026-01-01', discovered_at: '2026-01-01' },
      { id: '2', source_name: 'MangaPark', source_id: 'mp1', chapter_url: 'https://mangapark.com/1', published_at: '2026-01-02', discovered_at: '2026-01-02' },
    ];

    const mockSeriesSources: SeriesSourcePreference[] = [
      { id: '1', source_name: 'MangaDex', trust_score: 90 },
      { id: '2', source_name: 'MangaPark', trust_score: 80 },
    ];

    it('returns null for empty sources', () => {
      const result = selectBestSource([], [], {});
      expect(result.source).toBeNull();
      expect(result.reason).toBe('none');
    });

    it('prefers series-specific preference', () => {
      const result = selectBestSource(mockSources, mockSeriesSources, {
        preferredSourceSeries: 'MangaPark',
        preferredSourceGlobal: 'MangaDex',
      });
      expect(result.source?.source_name).toBe('MangaPark');
      expect(result.reason).toBe('preferred_series');
    });

    it('falls back to global preference', () => {
      const result = selectBestSource(mockSources, mockSeriesSources, {
        preferredSourceGlobal: 'MangaDex',
      });
      expect(result.source?.source_name).toBe('MangaDex');
      expect(result.reason).toBe('preferred_global');
    });

    it('falls back to trust score when no preference matches', () => {
      const result = selectBestSource(mockSources, mockSeriesSources, {
        preferredSourceSeries: 'NonExistent',
      });
      expect(result.source?.source_name).toBe('MangaDex'); // Higher trust score
      expect(result.reason).toBe('trust_score');
      expect(result.isFallback).toBe(true);
    });

    it('filters out unavailable sources', () => {
      const sourcesWithUnavailable: ChapterSource[] = [
        { ...mockSources[0], is_available: false },
        { ...mockSources[1], is_available: true },
      ];
      const result = selectBestSource(sourcesWithUnavailable, mockSeriesSources, {});
      expect(result.source?.source_name).toBe('MangaPark');
    });
  });

  // ============================================
  // VALIDATION TESTS
  // ============================================
  describe('Validation - Email', () => {
    it('validates correct emails', () => {
      expect(validateEmail('test@example.com')).toBe(true);
      expect(validateEmail('user.name@domain.co.uk')).toBe(true);
    });

    it('rejects invalid emails', () => {
      expect(validateEmail('invalid')).toBe(false);
      expect(validateEmail('@domain.com')).toBe(false);
      expect(validateEmail('user@')).toBe(false);
    });
  });

  describe('Validation - Username', () => {
    it('validates correct usernames', () => {
      expect(validateUsername('john_doe')).toBe(true);
      expect(validateUsername('user-123')).toBe(true);
      expect(validateUsername('TestUser')).toBe(true);
    });

    it('rejects invalid usernames', () => {
      expect(validateUsername('ab')).toBe(false); // Too short
      expect(validateUsername('a'.repeat(31))).toBe(false); // Too long
      expect(validateUsername('user@name')).toBe(false); // Invalid char
      expect(validateUsername('user name')).toBe(false); // Space
    });
  });

  describe('Validation - Filter Array Sanitization', () => {
    it('filters non-strings', () => {
      // @ts-expect-error - testing runtime behavior
      expect(sanitizeFilterArray([1, 'valid', null, 'test'])).toEqual(['valid', 'test']);
    });

    it('sanitizes each value', () => {
      expect(sanitizeFilterArray(['<script>bad</script>', 'good'])).toEqual(['bad', 'good']);
    });

    it('respects maxLength', () => {
      const longArray = Array(100).fill('item');
      expect(sanitizeFilterArray(longArray, 10).length).toBe(10);
    });

    it('handles non-array input', () => {
      // @ts-expect-error - testing runtime behavior
      expect(sanitizeFilterArray(null)).toEqual([]);
      // @ts-expect-error - testing runtime behavior
      expect(sanitizeFilterArray('string')).toEqual([]);
    });
  });

  describe('Validation - Title Case Normalization', () => {
    it('converts kebab-case to Title Case', () => {
      expect(toTitleCase('sci-fi')).toBe('Sci-Fi');
    });

    it('handles special cases', () => {
      expect(toTitleCase('boys-love')).toBe("Boys' Love");
      expect(toTitleCase('girls-love')).toBe("Girls' Love");
    });

    it('decodes URL-encoded strings', () => {
      expect(toTitleCase('Slice%20of%20Life')).toBe('Slice of Life');
    });

    it('preserves already formatted strings', () => {
      expect(toTitleCase('Action')).toBe('Action');
    });
  });

  // ============================================
  // ERROR HANDLING TESTS
  // ============================================
  describe('Error Handling - ApiError', () => {
    it('creates error with default status code', () => {
      const error = new ApiError('Test error');
      expect(error.statusCode).toBe(500);
      expect(error.name).toBe('ApiError');
    });

    it('creates error with custom status code and code', () => {
      const error = new ApiError('Not found', 404, 'NOT_FOUND');
      expect(error.statusCode).toBe(404);
      expect(error.code).toBe('NOT_FOUND');
    });

    it('extends Error class', () => {
      const error = new ApiError('Test');
      expect(error).toBeInstanceOf(Error);
    });
  });
});
