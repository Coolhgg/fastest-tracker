import { 
  checkRateLimit, 
  validateUUID, 
  sanitizeInput, 
  escapeILikePattern,
  validateUsername,
  sanitizeFilterArray,
  normalizeToTitleCase,
  validateOrigin,
  ApiError,
  ErrorCodes
} from '@/lib/api-utils';
import { calculateLevel, xpForLevel, calculateLevelProgress, addXp, MAX_XP } from '@/lib/gamification/xp';
import { isWhitelistedDomain, isInternalIP } from '@/lib/constants/image-whitelist';
import { validateSourceUrl, validateSourceId } from '@/lib/scrapers';
import { isTransientError } from '@/lib/prisma';

describe('Bug Bounty Comprehensive Tests - 2026', () => {
  describe('API Utils - Security', () => {
    describe('validateUUID', () => {
      it('should accept valid UUIDs', () => {
        expect(() => validateUUID('550e8400-e29b-41d4-a716-446655440000')).not.toThrow();
        expect(() => validateUUID('f47ac10b-58cc-4372-a567-0e02b2c3d479')).not.toThrow();
      });

      it('should reject invalid UUIDs', () => {
        expect(() => validateUUID('')).toThrow(ApiError);
        expect(() => validateUUID('not-a-uuid')).toThrow(ApiError);
        expect(() => validateUUID('550e8400-e29b-41d4-a716')).toThrow(ApiError);
        expect(() => validateUUID('../../etc/passwd')).toThrow(ApiError);
        expect(() => validateUUID('<script>alert(1)</script>')).toThrow(ApiError);
      });
    });

    describe('sanitizeInput', () => {
      it('should remove script tags', () => {
        expect(sanitizeInput('<script>alert(1)</script>')).toBe('');
        expect(sanitizeInput('hello<script>xss</script>world')).toBe('helloworld');
      });

      it('should remove dangerous protocols', () => {
        expect(sanitizeInput('javascript:alert(1)')).not.toContain('javascript:');
        expect(sanitizeInput('data:text/html,<script>alert(1)</script>')).not.toContain('data:');
      });

      it('should remove event handlers', () => {
        expect(sanitizeInput('onclick=alert(1)')).not.toContain('onclick=');
        expect(sanitizeInput('onerror=alert(1)')).not.toContain('onerror=');
      });

      it('should handle null bytes', () => {
        expect(sanitizeInput('test\x00injection')).toBe('testinjection');
      });

      it('should respect max length', () => {
        const longString = 'a'.repeat(200);
        expect(sanitizeInput(longString, 100).length).toBe(100);
      });
    });

    describe('escapeILikePattern', () => {
      it('should escape SQL ILIKE special characters', () => {
        expect(escapeILikePattern('test%')).toBe('test\\%');
        expect(escapeILikePattern('test_')).toBe('test\\_');
        expect(escapeILikePattern('test\\')).toBe('test\\\\');
        expect(escapeILikePattern('100%_match')).toBe('100\\%\\_match');
      });
    });

    describe('validateUsername', () => {
      it('should accept valid usernames', () => {
        expect(validateUsername('john_doe')).toBe(true);
        expect(validateUsername('user123')).toBe(true);
        expect(validateUsername('test-user')).toBe(true);
      });

      it('should reject invalid usernames', () => {
        expect(validateUsername('')).toBe(false);
        expect(validateUsername('ab')).toBe(false); // too short
        expect(validateUsername('a'.repeat(31))).toBe(false); // too long
        expect(validateUsername('user@domain')).toBe(false);
        expect(validateUsername('user name')).toBe(false);
        expect(validateUsername('<script>')).toBe(false);
      });
    });

    describe('sanitizeFilterArray', () => {
      it('should filter and sanitize array values', () => {
        const input = ['valid', '<script>xss</script>', '', 'ok'];
        const result = sanitizeFilterArray(input);
        expect(result).toContain('valid');
        expect(result).toContain('ok');
        expect(result).not.toContain('');
        expect(result.every(v => !v.includes('<script>'))).toBe(true);
      });

      it('should limit array length', () => {
        const input = Array(100).fill('test');
        expect(sanitizeFilterArray(input, 50).length).toBe(50);
      });
    });

    describe('normalizeToTitleCase', () => {
      it('should convert kebab-case to Title Case', () => {
        expect(normalizeToTitleCase(['slice-of-life'])).toContain('Slice Of Life');
        expect(normalizeToTitleCase(['sci-fi'])).toContain('Sci-Fi');
      });

      it('should handle already formatted values', () => {
        const result = normalizeToTitleCase(['Action', 'Romance']);
        expect(result).toContain('Action');
        expect(result).toContain('Romance');
      });
    });

    describe('Rate Limiting', () => {
      beforeEach(() => {
        jest.useFakeTimers();
      });

      afterEach(() => {
        jest.useRealTimers();
      });

      it('should allow requests within limit', () => {
        const key = `test-${Date.now()}`;
        expect(checkRateLimit(key, 5, 60000)).toBe(true);
        expect(checkRateLimit(key, 5, 60000)).toBe(true);
      });

      it('should block requests exceeding limit', () => {
        const key = `test-block-${Date.now()}`;
        for (let i = 0; i < 5; i++) {
          checkRateLimit(key, 5, 60000);
        }
        expect(checkRateLimit(key, 5, 60000)).toBe(false);
      });
    });
  });

  describe('XP and Gamification', () => {
    describe('calculateLevel', () => {
      it('should calculate correct levels', () => {
        expect(calculateLevel(0)).toBe(1);
        expect(calculateLevel(99)).toBe(1);
        expect(calculateLevel(100)).toBe(2);
        expect(calculateLevel(400)).toBe(3);
      });

      it('should handle edge cases', () => {
        expect(calculateLevel(-100)).toBe(1);
        expect(calculateLevel(MAX_XP + 1000)).toBe(calculateLevel(MAX_XP));
      });
    });

    describe('addXp', () => {
      it('should add XP correctly', () => {
        expect(addXp(100, 50)).toBe(150);
        expect(addXp(0, 100)).toBe(100);
      });

      it('should prevent overflow', () => {
        expect(addXp(MAX_XP - 10, 100)).toBe(MAX_XP);
        expect(addXp(MAX_XP, 1000)).toBe(MAX_XP);
      });

      it('should handle negative values', () => {
        expect(addXp(-100, 50)).toBe(0);
      });
    });

    describe('calculateLevelProgress', () => {
      it('should return progress between 0 and 1', () => {
        const progress = calculateLevelProgress(150);
        expect(progress).toBeGreaterThanOrEqual(0);
        expect(progress).toBeLessThanOrEqual(1);
      });
    });
  });

  describe('Image Proxy Security', () => {
    describe('isWhitelistedDomain', () => {
      it('should allow whitelisted domains', () => {
        expect(isWhitelistedDomain('https://cdn.mangadex.org/covers/123.jpg')).toBe(true);
        expect(isWhitelistedDomain('https://uploads.mangadex.org/data/xyz.png')).toBe(true);
        expect(isWhitelistedDomain('https://s4.anilist.co/file/anilistcdn/media/manga/cover/large/123.jpg')).toBe(true);
      });

      it('should block non-whitelisted domains', () => {
        expect(isWhitelistedDomain('https://evil.com/malicious.jpg')).toBe(false);
        expect(isWhitelistedDomain('https://attacker.org/steal.png')).toBe(false);
      });

      it('should handle invalid URLs', () => {
        expect(isWhitelistedDomain('not-a-url')).toBe(false);
        expect(isWhitelistedDomain('')).toBe(false);
      });
    });

    describe('isInternalIP - SSRF Protection', () => {
      it('should block localhost', () => {
        expect(isInternalIP('localhost')).toBe(true);
        expect(isInternalIP('127.0.0.1')).toBe(true);
        expect(isInternalIP('::1')).toBe(true);
        expect(isInternalIP('[::1]')).toBe(true);
      });

      it('should block private IP ranges', () => {
        expect(isInternalIP('10.0.0.1')).toBe(true);
        expect(isInternalIP('192.168.1.1')).toBe(true);
        expect(isInternalIP('172.16.0.1')).toBe(true);
        expect(isInternalIP('169.254.169.254')).toBe(true);
      });

      it('should block IPv6 mapped IPv4', () => {
        expect(isInternalIP('::ffff:127.0.0.1')).toBe(true);
        expect(isInternalIP('::ffff:192.168.1.1')).toBe(true);
      });

      it('should allow public IPs', () => {
        expect(isInternalIP('8.8.8.8')).toBe(false);
        expect(isInternalIP('cdn.mangadex.org')).toBe(false);
      });
    });
  });

  describe('Scraper Security', () => {
    describe('validateSourceUrl', () => {
      it('should allow valid source URLs', () => {
        expect(validateSourceUrl('https://api.mangadex.org/manga/123')).toBe(true);
        expect(validateSourceUrl('https://mangapark.io/title/xyz')).toBe(true);
      });

      it('should block non-whitelisted URLs', () => {
        expect(validateSourceUrl('https://evil.com/steal')).toBe(false);
        expect(validateSourceUrl('file:///etc/passwd')).toBe(false);
      });
    });

    describe('validateSourceId', () => {
      it('should accept valid source IDs', () => {
        expect(validateSourceId('abc123')).toBe(true);
        expect(validateSourceId('manga-title_v2')).toBe(true);
      });

      it('should reject invalid source IDs', () => {
        expect(validateSourceId('')).toBe(false);
        expect(validateSourceId('../../../etc/passwd')).toBe(false);
        expect(validateSourceId('a'.repeat(101))).toBe(false);
      });
    });
  });

  describe('Prisma Error Handling', () => {
    describe('isTransientError', () => {
      it('should identify connection errors as transient', () => {
        const connError = new Error('connection refused');
        expect(isTransientError(connError)).toBe(true);

        const poolError = new Error('connection pool timeout');
        expect(isTransientError(poolError)).toBe(true);
      });

      it('should NOT retry authentication errors', () => {
        const authError = new Error('password authentication failed for user "test"');
        expect(isTransientError(authError)).toBe(false);

        const accessError = new Error('permission denied for table users');
        expect(isTransientError(accessError)).toBe(false);
      });

      it('should handle Prisma error codes', () => {
        const p1001 = { code: 'P1001', message: 'Cannot connect to database' };
        expect(isTransientError(p1001)).toBe(true);

        const p1000 = { code: 'P1000', message: 'Authentication failed' };
        expect(isTransientError(p1000)).toBe(false);
      });
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty inputs gracefully', () => {
      expect(sanitizeInput('')).toBe('');
      expect(escapeILikePattern('')).toBe('');
      expect(sanitizeFilterArray([])).toEqual([]);
      expect(normalizeToTitleCase([])).toEqual([]);
    });

    it('should handle null/undefined inputs', () => {
      expect(sanitizeFilterArray(null as any)).toEqual([]);
      expect(normalizeToTitleCase(undefined as any)).toEqual([]);
    });

    it('should handle unicode and special characters', () => {
      const unicode = '日本語マンガ';
      expect(sanitizeInput(unicode)).toBe(unicode);
      
      const emoji = 'Test 🎉 Title';
      expect(sanitizeInput(emoji)).toBe(emoji);
    });
  });
});
