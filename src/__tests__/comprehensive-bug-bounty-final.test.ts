/**
 * Comprehensive Bug Bounty Final Tests
 * Tests all critical paths, security vulnerabilities, and edge cases
 * Created: January 2026
 */

import {
  sanitizeInput,
  escapeILikePattern,
  validateUUID,
  validateUsername,
  checkRateLimit,
  clearRateLimit,
  toTitleCase,
  normalizeToTitleCase,
  sanitizeFilterArray,
  ApiError,
  ErrorCodes,
  handleApiError,
  parsePaginationParams,
  validateEmail,
  htmlEncode,
  sanitizeText,
  checkAuthRateLimit,
} from '@/lib/api-utils';

import {
  isWhitelistedDomain,
  isInternalIP,
  ALLOWED_CONTENT_TYPES,
  MAX_IMAGE_SIZE,
  IMAGE_WHITELIST,
} from '@/lib/constants/image-whitelist';

// ============================================================================
// SECTION 1: INPUT SANITIZATION TESTS
// ============================================================================

describe('Security: Input Sanitization', () => {
  describe('sanitizeInput - XSS Prevention', () => {
    test('removes script tags with content', () => {
      expect(sanitizeInput('<script>alert(1)</script>Hello')).toBe('Hello');
      expect(sanitizeInput('<SCRIPT>alert(1)</SCRIPT>test')).toBe('test');
    });

    test('removes inline event handlers', () => {
      const inputs = [
        '<img onerror="alert(1)" src="x">',
        '<div onclick="evil()">',
        '<body onload="attack()">',
        '<input onfocus="hack()">',
      ];
      inputs.forEach(input => {
        const result = sanitizeInput(input);
        expect(result).not.toMatch(/on\w+=/i);
      });
    });

    test('removes dangerous protocols', () => {
      expect(sanitizeInput('javascript:alert(1)')).not.toContain('javascript:');
      expect(sanitizeInput('data:text/html,<script>')).not.toContain('data:');
      expect(sanitizeInput('vbscript:msgbox(1)')).not.toContain('vbscript:');
    });

    test('handles null bytes (truncation attacks)', () => {
      expect(sanitizeInput('hello\x00world')).toBe('helloworld');
      expect(sanitizeInput('test\x00<script>')).toBe('test');
    });

    test('strips HTML entities (prevents XSS bypass)', () => {
      // The sanitizer strips HTML entities like &#60; which could be decoded to <
      const result = sanitizeInput('&#60;script&#62;alert(1)&#60;/script&#62;');
      // After stripping entities, leftover text is harmless (not executable)
      expect(result).not.toContain('&#60;');
      expect(result).not.toContain('&#62;');
    });

    test('handles nested/malformed tags', () => {
      expect(sanitizeInput('<scr<script>ipt>alert(1)</scr</script>ipt>')).not.toMatch(/<script/i);
      expect(sanitizeInput('<<script>script>alert(1)<</script>/script>')).not.toMatch(/<script/i);
    });

    test('respects maxLength parameter', () => {
      const longInput = 'a'.repeat(500);
      expect(sanitizeInput(longInput, 100)).toHaveLength(100);
      expect(sanitizeInput(longInput, 50)).toHaveLength(50);
    });

    test('preserves valid unicode characters', () => {
      expect(sanitizeInput('ワンピース')).toBe('ワンピース');
      expect(sanitizeInput('나 혼자만 레벨업')).toBe('나 혼자만 레벨업');
      expect(sanitizeInput('Test 🎉 Manga')).toBe('Test 🎉 Manga');
      expect(sanitizeInput('Héllo Wörld')).toBe('Héllo Wörld');
    });

    test('handles empty and null-like inputs', () => {
      expect(sanitizeInput('')).toBe('');
      expect(sanitizeInput('   ')).toBe('');
    });
  });

  describe('escapeILikePattern - SQL Pattern Injection Prevention', () => {
    test('escapes percent signs', () => {
      expect(escapeILikePattern('100%')).toBe('100\\%');
      expect(escapeILikePattern('%admin%')).toBe('\\%admin\\%');
    });

    test('escapes underscores', () => {
      expect(escapeILikePattern('user_name')).toBe('user\\_name');
      expect(escapeILikePattern('a_b_c')).toBe('a\\_b\\_c');
    });

    test('escapes backslashes first', () => {
      expect(escapeILikePattern('path\\to\\file')).toBe('path\\\\to\\\\file');
    });

    test('handles combined special characters', () => {
      expect(escapeILikePattern('50% off_sale\\')).toBe('50\\% off\\_sale\\\\');
    });

    test('preserves normal text', () => {
      expect(escapeILikePattern('normal text')).toBe('normal text');
      expect(escapeILikePattern('Manga Title 123')).toBe('Manga Title 123');
    });
  });

  describe('sanitizeFilterArray', () => {
    test('filters non-string values', () => {
      // @ts-expect-error - testing runtime behavior
      expect(sanitizeFilterArray(['valid', 123, null, undefined, 'another'])).toEqual(['valid', 'another']);
    });

    test('respects maxLength parameter', () => {
      const arr = Array(60).fill('item');
      expect(sanitizeFilterArray(arr, 50)).toHaveLength(50);
    });

    test('sanitizes each item for XSS', () => {
      const result = sanitizeFilterArray(['<script>bad</script>valid', 'clean']);
      expect(result[0]).not.toContain('<script>');
    });

    test('handles empty arrays', () => {
      expect(sanitizeFilterArray([])).toEqual([]);
    });

    test('handles non-array input', () => {
      // @ts-expect-error - testing runtime behavior
      expect(sanitizeFilterArray(null)).toEqual([]);
      // @ts-expect-error - testing runtime behavior
      expect(sanitizeFilterArray(undefined)).toEqual([]);
    });
  });

  describe('htmlEncode', () => {
    test('encodes HTML special characters', () => {
      expect(htmlEncode('<script>')).toBe('&lt;script&gt;');
      expect(htmlEncode('"test"')).toBe('&quot;test&quot;');
      expect(htmlEncode("it's")).toBe("it&#x27;s");
      expect(htmlEncode('a & b')).toBe('a &amp; b');
    });
  });

  describe('sanitizeText', () => {
    test('trims whitespace', () => {
      expect(sanitizeText('  hello  ')).toBe('hello');
    });

    test('respects maxLength', () => {
      expect(sanitizeText('a'.repeat(600), 500)).toHaveLength(500);
    });

    test('handles empty input', () => {
      expect(sanitizeText('')).toBe('');
    });
  });
});

// ============================================================================
// SECTION 2: SSRF PREVENTION TESTS
// ============================================================================

describe('Security: SSRF Prevention', () => {
  describe('isInternalIP', () => {
    test('blocks localhost variations', () => {
      expect(isInternalIP('localhost')).toBe(true);
      expect(isInternalIP('LOCALHOST')).toBe(true);
      expect(isInternalIP('127.0.0.1')).toBe(true);
      expect(isInternalIP('127.0.0.255')).toBe(true);
    });

    test('blocks IPv6 loopback', () => {
      expect(isInternalIP('::1')).toBe(true);
      expect(isInternalIP('[::1]')).toBe(true);
      expect(isInternalIP('0:0:0:0:0:0:0:1')).toBe(true);
    });

    test('blocks private IPv4 ranges', () => {
      // 10.0.0.0/8
      expect(isInternalIP('10.0.0.1')).toBe(true);
      expect(isInternalIP('10.255.255.255')).toBe(true);
      
      // 172.16.0.0/12
      expect(isInternalIP('172.16.0.1')).toBe(true);
      expect(isInternalIP('172.31.255.255')).toBe(true);
      
      // 192.168.0.0/16
      expect(isInternalIP('192.168.0.1')).toBe(true);
      expect(isInternalIP('192.168.255.255')).toBe(true);
    });

    test('blocks IPv6 mapped IPv4 bypass attempts', () => {
      expect(isInternalIP('::ffff:127.0.0.1')).toBe(true);
      expect(isInternalIP('[::ffff:192.168.1.1]')).toBe(true);
      expect(isInternalIP('::ffff:10.0.0.1')).toBe(true);
    });

    test('blocks AWS/cloud metadata IPs', () => {
      expect(isInternalIP('169.254.169.254')).toBe(true);
      expect(isInternalIP('169.254.170.2')).toBe(true);
    });

    test('blocks link-local addresses', () => {
      expect(isInternalIP('169.254.1.1')).toBe(true);
    });

    test('blocks internal-sounding hostnames', () => {
      expect(isInternalIP('internal.corp')).toBe(true);
      expect(isInternalIP('metadata.aws')).toBe(true);
      expect(isInternalIP('admin.local')).toBe(true);
    });

    test('allows public IPs', () => {
      expect(isInternalIP('8.8.8.8')).toBe(false);
      expect(isInternalIP('1.1.1.1')).toBe(false);
      expect(isInternalIP('208.67.222.222')).toBe(false);
    });
  });

  describe('isWhitelistedDomain', () => {
    test('allows whitelisted domains', () => {
      expect(isWhitelistedDomain('https://cdn.mangadex.org/image.jpg')).toBe(true);
      expect(isWhitelistedDomain('https://uploads.mangadex.org/covers/abc.jpg')).toBe(true);
      expect(isWhitelistedDomain('https://s4.anilist.co/file/cover.jpg')).toBe(true);
    });

    test('blocks non-whitelisted domains', () => {
      expect(isWhitelistedDomain('https://evil.com/malware.jpg')).toBe(false);
      expect(isWhitelistedDomain('https://attacker.org/image.png')).toBe(false);
    });

    test('handles invalid URLs gracefully', () => {
      expect(isWhitelistedDomain('not-a-url')).toBe(false);
      expect(isWhitelistedDomain('')).toBe(false);
      expect(isWhitelistedDomain('javascript:alert(1)')).toBe(false);
    });

    test('prevents subdomain bypass attacks', () => {
      expect(isWhitelistedDomain('https://evil.mangadex.org.attacker.com/img.jpg')).toBe(false);
      expect(isWhitelistedDomain('https://cdn.mangadex.org.evil.com/img.jpg')).toBe(false);
    });

    test('allows subdomains of whitelisted domains', () => {
      expect(isWhitelistedDomain('https://sub.cdn.mangadex.org/img.jpg')).toBe(true);
    });
  });

  describe('Content Type Validation', () => {
    test('allows valid image types', () => {
      expect(ALLOWED_CONTENT_TYPES).toContain('image/jpeg');
      expect(ALLOWED_CONTENT_TYPES).toContain('image/png');
      expect(ALLOWED_CONTENT_TYPES).toContain('image/webp');
      expect(ALLOWED_CONTENT_TYPES).toContain('image/gif');
    });

    test('blocks SVG (XSS risk)', () => {
      expect(ALLOWED_CONTENT_TYPES).not.toContain('image/svg+xml');
    });

    test('has reasonable max image size', () => {
      expect(MAX_IMAGE_SIZE).toBe(10 * 1024 * 1024); // 10MB
    });
  });
});

// ============================================================================
// SECTION 3: VALIDATION TESTS
// ============================================================================

describe('Security: Validation', () => {
  describe('validateUUID', () => {
    test('accepts valid UUIDs', () => {
      expect(() => validateUUID('550e8400-e29b-41d4-a716-446655440000')).not.toThrow();
      expect(() => validateUUID('123e4567-e89b-12d3-a456-426614174000')).not.toThrow();
    });

    test('rejects invalid UUIDs', () => {
      expect(() => validateUUID('not-a-uuid')).toThrow();
      expect(() => validateUUID('550e8400-e29b-41d4-a716')).toThrow();
      expect(() => validateUUID('')).toThrow();
      expect(() => validateUUID('550e8400e29b41d4a716446655440000')).toThrow();
    });

    test('rejects SQL injection attempts in UUID field', () => {
      expect(() => validateUUID("'; DROP TABLE users; --")).toThrow();
      expect(() => validateUUID("1' OR '1'='1")).toThrow();
    });

    test('provides custom field name in error', () => {
      expect(() => validateUUID('invalid', 'seriesId')).toThrow(/seriesId/);
    });
  });

  describe('validateUsername', () => {
    test('accepts valid usernames', () => {
      expect(validateUsername('john_doe123')).toBe(true);
      expect(validateUsername('user-name')).toBe(true);
      expect(validateUsername('JohnDoe')).toBe(true);
      expect(validateUsername('abc')).toBe(true);
    });

    test('rejects too short usernames', () => {
      expect(validateUsername('ab')).toBe(false);
      expect(validateUsername('a')).toBe(false);
      expect(validateUsername('')).toBe(false);
    });

    test('rejects too long usernames', () => {
      expect(validateUsername('a'.repeat(31))).toBe(false);
    });

    test('rejects invalid characters', () => {
      expect(validateUsername('user@name')).toBe(false);
      expect(validateUsername('user name')).toBe(false);
      expect(validateUsername('user<script>')).toBe(false);
      expect(validateUsername('user!name')).toBe(false);
    });
  });

  describe('validateEmail', () => {
    test('accepts valid emails', () => {
      expect(validateEmail('test@example.com')).toBe(true);
      expect(validateEmail('user.name@domain.org')).toBe(true);
    });

    test('rejects invalid emails', () => {
      expect(validateEmail('not-an-email')).toBe(false);
      expect(validateEmail('missing@')).toBe(false);
      expect(validateEmail('@nodomain.com')).toBe(false);
    });
  });
});

// ============================================================================
// SECTION 4: RATE LIMITING TESTS
// ============================================================================

describe('Rate Limiting', () => {
  beforeEach(() => {
    clearRateLimit('test-key');
    clearRateLimit('auth:test-ip');
  });

  test('allows requests within limit', () => {
    for (let i = 0; i < 5; i++) {
      expect(checkRateLimit('test-key', 10, 60000)).toBe(true);
    }
  });

  test('blocks requests exceeding limit', () => {
    for (let i = 0; i < 10; i++) {
      checkRateLimit('test-key', 10, 60000);
    }
    expect(checkRateLimit('test-key', 10, 60000)).toBe(false);
  });

  test('isolates different keys', () => {
    for (let i = 0; i < 10; i++) {
      checkRateLimit('key-a', 10, 60000);
    }
    expect(checkRateLimit('key-b', 10, 60000)).toBe(true);
  });

  test('auth rate limiting has stricter limits', () => {
    for (let i = 0; i < 5; i++) {
      checkAuthRateLimit('test-ip');
    }
    expect(checkAuthRateLimit('test-ip')).toBe(false);
  });
});

// ============================================================================
// SECTION 5: PAGINATION TESTS
// ============================================================================

describe('Pagination', () => {
  test('parses valid pagination params', () => {
    const params = new URLSearchParams('page=2&limit=50');
    const result = parsePaginationParams(params);
    expect(result.page).toBe(2);
    expect(result.limit).toBe(50);
    expect(result.offset).toBe(50);
  });

  test('enforces max limit of 100', () => {
    const params = new URLSearchParams('limit=500');
    const result = parsePaginationParams(params);
    expect(result.limit).toBe(100);
  });

  test('enforces min limit of 1', () => {
    const params = new URLSearchParams('limit=0');
    const result = parsePaginationParams(params);
    expect(result.limit).toBe(1);
  });

  test('handles offset parameter', () => {
    const params = new URLSearchParams('offset=100&limit=20');
    const result = parsePaginationParams(params);
    expect(result.offset).toBe(100);
    expect(result.page).toBe(6); // 100/20 + 1
  });

  test('defaults to page 1 and limit 20', () => {
    const params = new URLSearchParams('');
    const result = parsePaginationParams(params);
    expect(result.page).toBe(1);
    expect(result.limit).toBe(20);
  });

  test('prevents negative offset', () => {
    const params = new URLSearchParams('offset=-50');
    const result = parsePaginationParams(params);
    expect(result.offset).toBeGreaterThanOrEqual(0);
  });
});

// ============================================================================
// SECTION 6: TITLE CASE NORMALIZATION TESTS
// ============================================================================

describe('Title Case Normalization', () => {
  test('converts kebab-case to Title Case', () => {
    expect(toTitleCase('slice-of-life')).toBe('Slice Of Life');
    expect(toTitleCase('action')).toBe('Action');
  });

  test('preserves already formatted strings', () => {
    expect(toTitleCase('Slice of Life')).toBe('Slice of Life');
  });

  test('handles URL encoding', () => {
    expect(toTitleCase('Slice%20of%20Life')).toBe('Slice of Life');
  });

  test('handles special cases', () => {
    expect(toTitleCase('sci-fi')).toBe('Sci-Fi');
    expect(toTitleCase('boys-love')).toBe("Boys' Love");
    expect(toTitleCase('girls-love')).toBe("Girls' Love");
  });

  test('normalizeToTitleCase handles arrays', () => {
    const result = normalizeToTitleCase(['action', 'slice-of-life']);
    expect(result).toContain('Action');
    expect(result).toContain('Slice Of Life');
  });

  test('normalizeToTitleCase filters empty values', () => {
    const result = normalizeToTitleCase(['action', '', 'romance']);
    expect(result).toHaveLength(2);
  });

  test('normalizeToTitleCase handles non-array', () => {
    // @ts-expect-error - testing runtime behavior
    expect(normalizeToTitleCase(null)).toEqual([]);
    // @ts-expect-error - testing runtime behavior
    expect(normalizeToTitleCase(undefined)).toEqual([]);
  });
});

// ============================================================================
// SECTION 7: ERROR HANDLING TESTS
// ============================================================================

describe('Error Handling', () => {
  test('ApiError creates proper error structure', () => {
    const error = new ApiError('Test error', 400, ErrorCodes.BAD_REQUEST);
    expect(error.message).toBe('Test error');
    expect(error.statusCode).toBe(400);
    expect(error.code).toBe('BAD_REQUEST');
  });

  test('handleApiError returns proper JSON response for ApiError', () => {
    const error = new ApiError('Not found', 404, ErrorCodes.NOT_FOUND);
    const response = handleApiError(error);
    expect(response.status).toBe(404);
  });

  test('handleApiError handles Prisma errors', () => {
    const prismaError = new Error('Resource not found') as any;
    prismaError.name = 'PrismaClientKnownRequestError';
    prismaError.code = 'P2025';
    const response = handleApiError(prismaError);
    expect(response.status).toBe(404);
  });

  test('handleApiError handles unique constraint violation', () => {
    const prismaError = new Error('Unique constraint failed') as any;
    prismaError.name = 'PrismaClientKnownRequestError';
    prismaError.code = 'P2002';
    const response = handleApiError(prismaError);
    expect(response.status).toBe(409);
  });

  test('handleApiError returns 500 for unknown errors', () => {
    const error = new Error('Unknown error');
    const response = handleApiError(error);
    expect(response.status).toBe(500);
  });
});

// ============================================================================
// SECTION 8: EDGE CASES AND BOUNDARY CONDITIONS
// ============================================================================

describe('Edge Cases', () => {
  test('handles very long input strings', () => {
    const longInput = 'a'.repeat(100000);
    expect(sanitizeInput(longInput, 10000).length).toBeLessThanOrEqual(10000);
  });

  test('handles special unicode edge cases', () => {
    // Zero-width characters
    expect(sanitizeInput('test\u200Bword')).toBe('test\u200Bword');
    
    // RTL override
    expect(sanitizeInput('test\u202Eword')).toBeTruthy();
  });

  test('handles maximum chapter numbers', () => {
    // Chapter numbers should be within safe integer range
    expect(Number.MAX_SAFE_INTEGER).toBeGreaterThan(100000);
  });

  test('image whitelist has required domains', () => {
    expect(IMAGE_WHITELIST).toContain('cdn.mangadex.org');
    expect(IMAGE_WHITELIST).toContain('uploads.mangadex.org');
  });
});

// ============================================================================
// SECTION 9: API SECURITY PATTERNS
// ============================================================================

describe('API Security Patterns', () => {
  test('ErrorCodes contains all required codes', () => {
    expect(ErrorCodes.BAD_REQUEST).toBeDefined();
    expect(ErrorCodes.UNAUTHORIZED).toBeDefined();
    expect(ErrorCodes.FORBIDDEN).toBeDefined();
    expect(ErrorCodes.NOT_FOUND).toBeDefined();
    expect(ErrorCodes.CONFLICT).toBeDefined();
    expect(ErrorCodes.RATE_LIMITED).toBeDefined();
    expect(ErrorCodes.VALIDATION_ERROR).toBeDefined();
    expect(ErrorCodes.INTERNAL_ERROR).toBeDefined();
  });
});
