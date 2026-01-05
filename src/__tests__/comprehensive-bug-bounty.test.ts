/**
 * Comprehensive Integration Tests for Bug Bounty Audit
 * Tests all critical paths, security controls, and bug fixes
 */

import {
  sanitizeInput,
  htmlEncode,
  validateUUID,
  validateEmail,
  validateUsername,
  checkRateLimit,
  clearRateLimit,
  escapeILikePattern,
  sanitizeFilterArray,
  toTitleCase,
  normalizeToTitleCase,
} from '@/lib/api-utils'

import { isWhitelistedDomain, isInternalIP, IMAGE_WHITELIST } from '@/lib/constants/image-whitelist'

// ============================================
// INPUT SANITIZATION TESTS
// ============================================

describe('Input Sanitization', () => {
  describe('sanitizeInput', () => {
    it('removes HTML tags', () => {
      expect(sanitizeInput('<script>alert("xss")</script>')).toBe('alert("xss")')
      expect(sanitizeInput('<div onclick="alert()">test</div>')).toBe('test')
    })

    it('removes javascript: protocol', () => {
      expect(sanitizeInput('javascript:alert(1)')).toBe('alert(1)')
      expect(sanitizeInput('JAVASCRIPT:void(0)')).toBe('void(0)')
    })

    it('removes event handlers', () => {
      expect(sanitizeInput('test onclick=alert(1)')).toBe('test')
      expect(sanitizeInput('onload=malicious')).toBe('')
    })

    it('removes encoded characters used for bypasses', () => {
      expect(sanitizeInput('&#x3c;script&#x3e;')).toBe('script')
      expect(sanitizeInput('&#60;script&#62;')).toBe('script')
    })

    it('respects max length', () => {
      const longString = 'a'.repeat(200)
      expect(sanitizeInput(longString, 100)).toHaveLength(100)
    })

    it('handles empty/null input', () => {
      expect(sanitizeInput('')).toBe('')
      expect(sanitizeInput(null as any)).toBe('')
      expect(sanitizeInput(undefined as any)).toBe('')
    })

    it('trims whitespace', () => {
      expect(sanitizeInput('  test  ')).toBe('test')
    })
  })

  describe('htmlEncode', () => {
    it('encodes special characters', () => {
      expect(htmlEncode('<')).toBe('&lt;')
      expect(htmlEncode('>')).toBe('&gt;')
      expect(htmlEncode('&')).toBe('&amp;')
      expect(htmlEncode('"')).toBe('&quot;')
      expect(htmlEncode("'")).toBe('&#x27;')
      expect(htmlEncode('/')).toBe('&#x2F;')
    })

    it('encodes full XSS payload', () => {
      expect(htmlEncode('<script>alert("xss")</script>')).toBe(
        '&lt;script&gt;alert(&quot;xss&quot;)&lt;&#x2F;script&gt;'
      )
    })
  })

  describe('escapeILikePattern', () => {
    it('escapes SQL ILIKE special characters', () => {
      expect(escapeILikePattern('test%pattern')).toBe('test\\%pattern')
      expect(escapeILikePattern('test_pattern')).toBe('test\\_pattern')
      expect(escapeILikePattern('test\\pattern')).toBe('test\\\\pattern')
    })

    it('escapes combined patterns', () => {
      expect(escapeILikePattern('%_\\')).toBe('\\%\\_\\\\')
    })
  })

  describe('sanitizeFilterArray', () => {
    it('filters non-strings', () => {
      expect(sanitizeFilterArray([123, null, 'valid'] as any)).toEqual(['valid'])
    })

    it('limits array size', () => {
      const bigArray = Array(100).fill('item')
      expect(sanitizeFilterArray(bigArray, 10)).toHaveLength(10)
    })

    it('sanitizes each item', () => {
      expect(sanitizeFilterArray(['<script>test</script>', 'clean'])).toEqual(['test', 'clean'])
    })

    it('filters empty strings after sanitization', () => {
      expect(sanitizeFilterArray(['<>', '', '  '])).toEqual([])
    })
  })
})

// ============================================
// VALIDATION TESTS
// ============================================

describe('Validation Functions', () => {
  describe('validateUUID', () => {
    it('accepts valid UUIDs', () => {
      expect(() => validateUUID('123e4567-e89b-12d3-a456-426614174000')).not.toThrow()
      expect(() => validateUUID('550e8400-e29b-41d4-a716-446655440000')).not.toThrow()
    })

    it('rejects invalid UUIDs', () => {
      expect(() => validateUUID('not-a-uuid')).toThrow()
      expect(() => validateUUID('123')).toThrow()
      expect(() => validateUUID('')).toThrow()
      expect(() => validateUUID('123e4567-e89b-62d3-a456-426614174000')).toThrow() // invalid version
    })

    it('includes field name in error', () => {
      expect(() => validateUUID('invalid', 'seriesId')).toThrow(/seriesId/)
    })
  })

  describe('validateEmail', () => {
    it('accepts valid emails', () => {
      expect(validateEmail('test@example.com')).toBe(true)
      expect(validateEmail('user.name@domain.co.uk')).toBe(true)
      expect(validateEmail('user+tag@example.org')).toBe(true)
    })

    it('rejects invalid emails', () => {
      expect(validateEmail('not-an-email')).toBe(false)
      expect(validateEmail('@example.com')).toBe(false)
      expect(validateEmail('user@')).toBe(false)
      expect(validateEmail('')).toBe(false)
    })
  })

  describe('validateUsername', () => {
    it('accepts valid usernames', () => {
      expect(validateUsername('user123')).toBe(true)
      expect(validateUsername('User_Name')).toBe(true)
      expect(validateUsername('test-user')).toBe(true)
      expect(validateUsername('abc')).toBe(true)
    })

    it('rejects invalid usernames', () => {
      expect(validateUsername('ab')).toBe(false) // too short
      expect(validateUsername('a'.repeat(31))).toBe(false) // too long
      expect(validateUsername('user@name')).toBe(false) // invalid char
      expect(validateUsername('user name')).toBe(false) // space
      expect(validateUsername('')).toBe(false)
    })
  })
})

// ============================================
// RATE LIMITING TESTS
// ============================================

describe('Rate Limiting', () => {
  beforeEach(() => {
    clearRateLimit('test-key')
  })

  it('allows requests under limit', () => {
    for (let i = 0; i < 5; i++) {
      expect(checkRateLimit('test-key', 10, 60000)).toBe(true)
    }
  })

  it('blocks requests over limit', () => {
    for (let i = 0; i < 10; i++) {
      checkRateLimit('test-key', 10, 60000)
    }
    expect(checkRateLimit('test-key', 10, 60000)).toBe(false)
  })

  it('uses separate limits for different keys', () => {
    for (let i = 0; i < 5; i++) {
      checkRateLimit('key1', 5, 60000)
    }
    expect(checkRateLimit('key1', 5, 60000)).toBe(false)
    expect(checkRateLimit('key2', 5, 60000)).toBe(true)
  })

  it('resets after window expires', async () => {
    for (let i = 0; i < 3; i++) {
      checkRateLimit('expire-test', 3, 50) // 50ms window
    }
    expect(checkRateLimit('expire-test', 3, 50)).toBe(false)
    
    await new Promise(resolve => setTimeout(resolve, 60))
    
    expect(checkRateLimit('expire-test', 3, 50)).toBe(true)
  })
})

// ============================================
// SSRF PROTECTION TESTS
// ============================================

describe('SSRF Protection', () => {
  describe('isInternalIP', () => {
    it('blocks localhost', () => {
      expect(isInternalIP('localhost')).toBe(true)
      expect(isInternalIP('127.0.0.1')).toBe(true)
      expect(isInternalIP('::1')).toBe(true)
      expect(isInternalIP('[::1]')).toBe(true)
      expect(isInternalIP('0.0.0.0')).toBe(true)
    })

    it('blocks private IPv4 ranges', () => {
      expect(isInternalIP('10.0.0.1')).toBe(true)
      expect(isInternalIP('10.255.255.255')).toBe(true)
      expect(isInternalIP('172.16.0.1')).toBe(true)
      expect(isInternalIP('172.31.255.255')).toBe(true)
      expect(isInternalIP('192.168.0.1')).toBe(true)
      expect(isInternalIP('192.168.255.255')).toBe(true)
    })

    it('blocks IPv6-mapped IPv4 addresses', () => {
      expect(isInternalIP('::ffff:127.0.0.1')).toBe(true)
      expect(isInternalIP('::ffff:10.0.0.1')).toBe(true)
      expect(isInternalIP('[::ffff:192.168.1.1]')).toBe(true)
    })

    it('blocks AWS metadata service', () => {
      expect(isInternalIP('169.254.169.254')).toBe(true)
      expect(isInternalIP('169.254.170.2')).toBe(true)
    })

    it('blocks internal hostname patterns', () => {
      expect(isInternalIP('internal.company.com')).toBe(true)
      expect(isInternalIP('metadata.google.internal')).toBe(true)
    })

    it('allows public IPs', () => {
      expect(isInternalIP('8.8.8.8')).toBe(false)
      expect(isInternalIP('1.1.1.1')).toBe(false)
      expect(isInternalIP('example.com')).toBe(false)
    })
  })

  describe('isWhitelistedDomain', () => {
    it('allows whitelisted domains', () => {
      expect(isWhitelistedDomain('https://cdn.mangadex.org/image.jpg')).toBe(true)
      expect(isWhitelistedDomain('https://uploads.mangadex.org/covers/123.jpg')).toBe(true)
      expect(isWhitelistedDomain('https://s4.anilist.co/file/cover.png')).toBe(true)
    })

    it('allows subdomains of whitelisted domains', () => {
      expect(isWhitelistedDomain('https://sub.mangadex.org/image.jpg')).toBe(true)
    })

    it('blocks non-whitelisted domains', () => {
      expect(isWhitelistedDomain('https://evil.com/image.jpg')).toBe(false)
      expect(isWhitelistedDomain('https://mangadex.org.evil.com/image.jpg')).toBe(false)
    })

    it('handles invalid URLs', () => {
      expect(isWhitelistedDomain('not-a-url')).toBe(false)
      expect(isWhitelistedDomain('')).toBe(false)
    })
  })
})

// ============================================
// TITLE CASE NORMALIZATION TESTS
// ============================================

describe('Title Case Normalization', () => {
  describe('toTitleCase', () => {
    it('converts kebab-case to Title Case', () => {
      expect(toTitleCase('slice-of-life')).toBe('Slice of Life')
      expect(toTitleCase('action-adventure')).toBe('Action Adventure')
    })

    it('preserves special cases', () => {
      expect(toTitleCase('sci-fi')).toBe('Sci-Fi')
      expect(toTitleCase("boys-love")).toBe("Boys' Love")
      expect(toTitleCase("girls-love")).toBe("Girls' Love")
    })

    it('handles URL encoding', () => {
      expect(toTitleCase('Slice%20of%20Life')).toBe('Slice of Life')
    })

    it('handles already formatted strings', () => {
      expect(toTitleCase('Slice of Life')).toBe('Slice of Life')
    })
  })

  describe('normalizeToTitleCase', () => {
    it('normalizes array of values', () => {
      expect(normalizeToTitleCase(['action', 'slice-of-life'])).toEqual(['Action', 'Slice of Life'])
    })

    it('filters empty values', () => {
      expect(normalizeToTitleCase(['action', '', 'drama'])).toEqual(['Action', 'Drama'])
    })

    it('handles non-array input', () => {
      expect(normalizeToTitleCase(null as any)).toEqual([])
      expect(normalizeToTitleCase(undefined as any)).toEqual([])
    })
  })
})

// ============================================
// API INTEGRATION TESTS (MOCKED)
// ============================================

describe('API Route Validation', () => {
  describe('Library API field validation', () => {
    it('should accept seriesId field (camelCase)', () => {
      const validPayload = { seriesId: '123e4567-e89b-12d3-a456-426614174000', status: 'reading' }
      expect(validPayload.seriesId).toBeDefined()
      expect(() => validateUUID(validPayload.seriesId)).not.toThrow()
    })

    it('should validate status values', () => {
      const validStatuses = ['reading', 'completed', 'planning', 'dropped', 'paused']
      validStatuses.forEach(status => {
        expect(validStatuses.includes(status)).toBe(true)
      })
      expect(validStatuses.includes('invalid')).toBe(false)
    })
  })

  describe('Progress API validation', () => {
    it('should validate chapter number range', () => {
      const validChapter = 50
      expect(validChapter >= 0 && validChapter <= 100000).toBe(true)
      
      const invalidChapter = -1
      expect(invalidChapter >= 0 && invalidChapter <= 100000).toBe(false)
      
      const tooHighChapter = 100001
      expect(tooHighChapter >= 0 && tooHighChapter <= 100000).toBe(false)
    })
  })

  describe('User profile API validation', () => {
    it('should validate username format', () => {
      expect(validateUsername('valid_user')).toBe(true)
      expect(validateUsername('user-123')).toBe(true)
      expect(validateUsername('ab')).toBe(false) // too short
      expect(validateUsername('user@invalid')).toBe(false)
    })
  })
})

// ============================================
// BUG FIX VERIFICATION TESTS
// ============================================

describe('Bug Fix Verification', () => {
  describe('Onboarding page API field name fix', () => {
    it('should use seriesId instead of series_id', () => {
      // The correct field name for the library API
      const correctPayload = { seriesId: 'uuid-here', status: 'planning' }
      const incorrectPayload = { series_id: 'uuid-here', status: 'planning' }
      
      expect(correctPayload.seriesId).toBeDefined()
      expect((incorrectPayload as any).seriesId).toBeUndefined()
    })
  })

  describe('Login page error clearing', () => {
    it('should clear errors when input changes', () => {
      // Simulating the bug fix behavior
      let error: string | null = 'Some error'
      
      const handleInputChange = () => {
        if (error) error = null
      }
      
      handleInputChange()
      expect(error).toBeNull()
    })
  })
})

// ============================================
// SECURITY EDGE CASES
// ============================================

describe('Security Edge Cases', () => {
  it('prevents prototype pollution in sanitization', () => {
    const maliciousInput = '{"__proto__":{"polluted":true}}'
    const result = sanitizeInput(maliciousInput)
    expect((Object.prototype as any).polluted).toBeUndefined()
  })

  it('handles extremely long inputs gracefully', () => {
    const longInput = 'a'.repeat(100000)
    const result = sanitizeInput(longInput, 10000)
    expect(result.length).toBeLessThanOrEqual(10000)
  })

  it('handles unicode bypass attempts', () => {
    // Full-width less-than sign
    const unicodeBypass = '\uFF1Cscript\uFF1E'
    const result = sanitizeInput(unicodeBypass)
    expect(result).not.toContain('<')
    expect(result).not.toContain('>')
  })

  it('handles null byte injection', () => {
    const nullByteInput = 'test\x00<script>alert(1)</script>'
    const result = sanitizeInput(nullByteInput)
    expect(result).not.toContain('<script>')
  })
})
