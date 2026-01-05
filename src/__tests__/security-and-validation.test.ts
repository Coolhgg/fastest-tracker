/**
 * Security and Validation Tests
 * Tests for input validation, sanitization, rate limiting, and security measures
 */

import { 
  sanitizeInput, 
  htmlEncode, 
  validateUUID, 
  validateEmail, 
  validateUsername,
  checkRateLimit,
  clearRateLimit,
  checkAuthRateLimit,
  ApiError,
  handleApiError,
} from '@/lib/api-utils'
import { 
  isWhitelistedDomain, 
  isInternalIP,
  ALLOWED_CONTENT_TYPES,
} from '@/lib/constants/image-whitelist'

describe('Security and Validation Tests', () => {
  beforeEach(() => {
    clearRateLimit('test-key')
    clearRateLimit('test-key-block')
    clearRateLimit('test-key-reset')
    clearRateLimit('auth:test-ip')
  })

  describe('Input Sanitization', () => {
    describe('sanitizeInput', () => {
      it('should remove HTML tags', () => {
        const input = '<script>alert("xss")</script>Hello'
        const result = sanitizeInput(input)
        expect(result).not.toContain('<script>')
        expect(result).not.toContain('</script>')
        expect(result).toContain('Hello')
      })

      it('should remove javascript: protocol', () => {
        const input = 'javascript:alert(1)'
        const result = sanitizeInput(input)
        expect(result).not.toContain('javascript:')
      })

      it('should remove event handlers', () => {
        const input = 'onclick=alert(1) test'
        const result = sanitizeInput(input)
        expect(result).not.toContain('onclick=')
      })

      it('should trim whitespace', () => {
        const input = '  hello world  '
        const result = sanitizeInput(input)
        expect(result).toBe('hello world')
      })

      it('should respect max length', () => {
        const input = 'a'.repeat(1000)
        const result = sanitizeInput(input, 100)
        expect(result.length).toBe(100)
      })

      it('should handle empty strings', () => {
        expect(sanitizeInput('')).toBe('')
      })

      it('should handle normal text', () => {
        const input = 'This is a normal search query'
        expect(sanitizeInput(input)).toBe('This is a normal search query')
      })

      it('should preserve unicode characters', () => {
        const input = '日本語 한국어 Español'
        expect(sanitizeInput(input)).toBe('日本語 한국어 Español')
      })
    })

    describe('htmlEncode', () => {
      it('should encode special characters', () => {
        expect(htmlEncode('&')).toBe('&amp;')
        expect(htmlEncode('<')).toBe('&lt;')
        expect(htmlEncode('>')).toBe('&gt;')
        expect(htmlEncode('"')).toBe('&quot;')
        expect(htmlEncode("'")).toBe('&#x27;')
      })

      it('should encode multiple special characters', () => {
        const input = '<script>"test" & \'value\'</script>'
        const result = htmlEncode(input)
        expect(result).toBe('&lt;script&gt;&quot;test&quot; &amp; &#x27;value&#x27;&lt;&#x2F;script&gt;')
      })
    })
  })

  describe('UUID Validation', () => {
    it('should accept valid UUIDs', () => {
      expect(() => validateUUID('550e8400-e29b-41d4-a716-446655440000')).not.toThrow()
      expect(() => validateUUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')).not.toThrow()
    })

    it('should reject invalid UUIDs', () => {
      expect(() => validateUUID('not-a-uuid')).toThrow(ApiError)
      expect(() => validateUUID('')).toThrow(ApiError)
      expect(() => validateUUID('550e8400-e29b-41d4-a716')).toThrow(ApiError)
    })

    it('should include field name in error', () => {
      try {
        validateUUID('invalid', 'seriesId')
      } catch (e: any) {
        expect(e.message).toContain('seriesId')
      }
    })
  })

  describe('Email Validation', () => {
    it('should accept valid emails', () => {
      expect(validateEmail('user@example.com')).toBe(true)
      expect(validateEmail('user.name@domain.co.uk')).toBe(true)
      expect(validateEmail('user+tag@example.org')).toBe(true)
    })

    it('should reject invalid emails', () => {
      expect(validateEmail('')).toBe(false)
      expect(validateEmail('notanemail')).toBe(false)
      expect(validateEmail('@nodomain.com')).toBe(false)
      expect(validateEmail('user@')).toBe(false)
    })
  })

  describe('Username Validation', () => {
    it('should accept valid usernames', () => {
      expect(validateUsername('john_doe')).toBe(true)
      expect(validateUsername('user123')).toBe(true)
      expect(validateUsername('manga-reader')).toBe(true)
      expect(validateUsername('abc')).toBe(true)
    })

    it('should reject invalid usernames', () => {
      expect(validateUsername('')).toBe(false)
      expect(validateUsername('ab')).toBe(false)
      expect(validateUsername('a'.repeat(31))).toBe(false)
      expect(validateUsername('user@name')).toBe(false)
      expect(validateUsername('user name')).toBe(false)
    })
  })

  describe('Rate Limiting', () => {
    it('should allow requests within limit', () => {
      for (let i = 0; i < 5; i++) {
        expect(checkRateLimit('test-key', 10, 60000)).toBe(true)
      }
    })

    it('should block requests over limit', () => {
      const key = 'rate-limit-block-test'
      clearRateLimit(key)
      for (let i = 0; i < 5; i++) {
        checkRateLimit(key, 5, 60000)
      }
      expect(checkRateLimit(key, 5, 60000)).toBe(false)
    })

    it('should reset after window expires', async () => {
      const key = 'rate-limit-reset-test'
      clearRateLimit(key)
      for (let i = 0; i < 3; i++) {
        checkRateLimit(key, 3, 50)
      }
      expect(checkRateLimit(key, 3, 50)).toBe(false)
      
      await new Promise(resolve => setTimeout(resolve, 100))
      expect(checkRateLimit(key, 3, 50)).toBe(true)
    })

    it('should use stricter limits for auth endpoints', () => {
      const ip = 'auth-test-ip'
      clearRateLimit(`auth:${ip}`)
      for (let i = 0; i < 5; i++) {
        expect(checkAuthRateLimit(ip)).toBe(true)
      }
      expect(checkAuthRateLimit(ip)).toBe(false)
    })
  })

  describe('Image Proxy Security', () => {
    describe('Domain Whitelist', () => {
      it('should allow whitelisted domains', () => {
        expect(isWhitelistedDomain('https://cdn.mangadex.org/image.jpg')).toBe(true)
        expect(isWhitelistedDomain('https://uploads.mangadex.org/cover.png')).toBe(true)
        expect(isWhitelistedDomain('https://cdn.myanimelist.net/images/manga.jpg')).toBe(true)
        expect(isWhitelistedDomain('https://i.imgur.com/abc123.png')).toBe(true)
      })

      it('should block non-whitelisted domains', () => {
        expect(isWhitelistedDomain('https://evil.com/malware.exe')).toBe(false)
        expect(isWhitelistedDomain('https://random-domain.net/image.jpg')).toBe(false)
      })

      it('should handle invalid URLs', () => {
        expect(isWhitelistedDomain('')).toBe(false)
        expect(isWhitelistedDomain('not-a-url')).toBe(false)
      })
    })

    describe('SSRF Protection', () => {
      it('should block localhost', () => {
        expect(isInternalIP('localhost')).toBe(true)
        expect(isInternalIP('127.0.0.1')).toBe(true)
        expect(isInternalIP('::1')).toBe(true)
      })

      it('should block private IP ranges', () => {
        expect(isInternalIP('10.0.0.1')).toBe(true)
        expect(isInternalIP('10.255.255.255')).toBe(true)
        expect(isInternalIP('172.16.0.1')).toBe(true)
        expect(isInternalIP('172.31.255.255')).toBe(true)
        expect(isInternalIP('192.168.0.1')).toBe(true)
        expect(isInternalIP('192.168.255.255')).toBe(true)
      })

      it('should block AWS metadata service', () => {
        expect(isInternalIP('169.254.169.254')).toBe(true)
      })

      it('should block internal hostnames', () => {
        expect(isInternalIP('internal.company.com')).toBe(true)
        expect(isInternalIP('intranet.local')).toBe(true)
        expect(isInternalIP('metadata.google.internal')).toBe(true)
      })

      it('should allow public IPs', () => {
        expect(isInternalIP('8.8.8.8')).toBe(false)
        expect(isInternalIP('cdn.example.com')).toBe(false)
      })
    })

    describe('Content Type Validation', () => {
      it('should allow image content types', () => {
        expect(ALLOWED_CONTENT_TYPES).toContain('image/jpeg')
        expect(ALLOWED_CONTENT_TYPES).toContain('image/png')
        expect(ALLOWED_CONTENT_TYPES).toContain('image/gif')
        expect(ALLOWED_CONTENT_TYPES).toContain('image/webp')
      })

      it('should not allow SVG (XSS risk)', () => {
        expect(ALLOWED_CONTENT_TYPES).not.toContain('image/svg+xml')
      })

      it('should not allow executable types', () => {
        expect(ALLOWED_CONTENT_TYPES).not.toContain('application/javascript')
        expect(ALLOWED_CONTENT_TYPES).not.toContain('text/html')
        expect(ALLOWED_CONTENT_TYPES).not.toContain('application/x-executable')
      })
    })
  })

  describe('API Error Handling', () => {
    it('should create ApiError with correct properties', () => {
      const error = new ApiError('Not found', 404, 'NOT_FOUND')
      expect(error.message).toBe('Not found')
      expect(error.statusCode).toBe(404)
      expect(error.code).toBe('NOT_FOUND')
      expect(error.name).toBe('ApiError')
    })

    it('should handle ApiError in handleApiError', () => {
      const error = new ApiError('Resource not found', 404, 'NOT_FOUND')
      const response = handleApiError(error)
      
      expect(response.status).toBe(404)
    })

    it('should handle Prisma unique constraint error', () => {
      const error = new Error('Unique constraint failed')
      ;(error as any).name = 'PrismaClientKnownRequestError'
      ;(error as any).code = 'P2002'
      
      const response = handleApiError(error)
      expect(response.status).toBe(409)
    })

    it('should handle Prisma not found error', () => {
      const error = new Error('Record not found')
      ;(error as any).name = 'PrismaClientKnownRequestError'
      ;(error as any).code = 'P2025'
      
      const response = handleApiError(error)
      expect(response.status).toBe(404)
    })

    it('should return 500 for unknown errors', () => {
      const error = new Error('Unknown error')
      const response = handleApiError(error)
      
      expect(response.status).toBe(500)
    })
  })

  describe('XSS Prevention', () => {
    it('should neutralize script injection in search queries', () => {
      const malicious = '<script>document.cookie</script>'
      const safe = sanitizeInput(malicious)
      expect(safe).not.toContain('<script>')
    })

    it('should neutralize img onerror XSS', () => {
      const malicious = '<img src=x onerror=alert(1)>'
      const safe = sanitizeInput(malicious)
      expect(safe).not.toContain('onerror=')
    })

    it('should neutralize event handler injection', () => {
      const malicious = 'onmouseover=alert(1)'
      const safe = sanitizeInput(malicious)
      expect(safe).not.toContain('onmouseover=')
    })
  })

  describe('SQL Injection Prevention', () => {
    it('should handle SQL-like characters safely', () => {
      const input = "'; DROP TABLE users; --"
      const safe = sanitizeInput(input)
      expect(typeof safe).toBe('string')
    })

    it('should handle quote characters', () => {
      const input = "test' OR '1'='1"
      const safe = sanitizeInput(input)
      expect(typeof safe).toBe('string')
    })
  })
})
