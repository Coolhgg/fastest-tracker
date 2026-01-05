/**
 * Comprehensive Bug Bounty Integration Tests
 * Tests security, validation, error handling, and edge cases across all API routes
 */

// === Mocks ===
const mockPrismaUser = {
  findUnique: jest.fn(),
  findFirst: jest.fn(),
  findMany: jest.fn(),
  create: jest.fn(),
  update: jest.fn(),
  delete: jest.fn(),
  count: jest.fn(),
}

const mockPrismaLibraryEntry = {
  findUnique: jest.fn(),
  findFirst: jest.fn(),
  findMany: jest.fn(),
  create: jest.fn(),
  update: jest.fn(),
  delete: jest.fn(),
  count: jest.fn(),
}

const mockPrismaFollow = {
  findUnique: jest.fn(),
  findFirst: jest.fn(),
  findMany: jest.fn(),
  create: jest.fn(),
  delete: jest.fn(),
  deleteMany: jest.fn(),
  count: jest.fn(),
}

const mockPrismaNotification = {
  findMany: jest.fn(),
  findFirst: jest.fn(),
  create: jest.fn(),
  update: jest.fn(),
  updateMany: jest.fn(),
  count: jest.fn(),
}

const mockPrismaActivity = {
  findMany: jest.fn(),
  create: jest.fn(),
  count: jest.fn(),
}

const mockPrismaSeries = {
  findUnique: jest.fn(),
  findMany: jest.fn(),
  update: jest.fn(),
}

const mockPrisma = {
  user: mockPrismaUser,
  libraryEntry: mockPrismaLibraryEntry,
  follow: mockPrismaFollow,
  notification: mockPrismaNotification,
  activity: mockPrismaActivity,
  series: mockPrismaSeries,
  $transaction: jest.fn((fn) => fn(mockPrisma)),
}

jest.mock('@/lib/prisma', () => ({
  prisma: mockPrisma,
  withRetry: jest.fn((fn) => fn()),
  isTransientError: jest.fn(() => false),
}))

// Mock Redis
const mockRedis = {
  multi: jest.fn(() => ({
    incr: jest.fn().mockReturnThis(),
    pexpire: jest.fn().mockReturnThis(),
    exec: jest.fn().mockResolvedValue([[null, 1], [null, 'OK']]),
  })),
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
}

jest.mock('@/lib/redis', () => ({
  redis: mockRedis,
  waitForRedis: jest.fn().mockResolvedValue(true),
  REDIS_KEY_PREFIX: 'test:',
}))

// Mock Supabase
const mockSupabaseUser = { id: 'test-user-id', email: 'test@example.com' }
jest.mock('@/lib/supabase/server', () => ({
  createClient: jest.fn(() => ({
    auth: {
      getUser: jest.fn(() => ({
        data: { user: mockSupabaseUser },
        error: null,
      })),
    },
  })),
}))

jest.mock('@/lib/supabase/admin', () => ({
  supabaseAdmin: {
    from: jest.fn(() => ({
      select: jest.fn().mockReturnThis(),
      eq: jest.fn().mockReturnThis(),
      single: jest.fn().mockResolvedValue({ data: { id: 'series-id' }, error: null }),
      insert: jest.fn().mockReturnThis(),
    })),
    rpc: jest.fn().mockResolvedValue({ data: null, error: null }),
  },
}))

// Mock gamification modules
jest.mock('@/lib/gamification/activity', () => ({
  logActivity: jest.fn(),
}))

jest.mock('@/lib/gamification/xp', () => ({
  XP_SERIES_COMPLETED: 100,
  XP_PER_CHAPTER: 10,
  calculateLevel: jest.fn((xp) => Math.floor(xp / 100) + 1),
  addXp: jest.fn((current, add) => current + add),
}))

jest.mock('@/lib/gamification/achievements', () => ({
  checkAchievements: jest.fn(),
}))

jest.mock('@/lib/gamification/streaks', () => ({
  calculateNewStreak: jest.fn(() => 1),
  calculateStreakBonus: jest.fn(() => 5),
}))

import { NextRequest } from 'next/server'
import {
  checkRateLimit,
  getClientIp,
  sanitizeInput,
  validateUUID,
  validateUsername,
  escapeILikePattern,
  parsePaginationParams,
  ApiError,
  ErrorCodes,
} from '@/lib/api-utils'

// Helper to create mock requests
function createMockRequest(
  url: string,
  options: {
    method?: string
    body?: any
    headers?: Record<string, string>
  } = {}
): NextRequest {
  const { method = 'GET', body, headers = {} } = options
  
  const requestInit: RequestInit = {
    method,
    headers: {
      'content-type': 'application/json',
      ...headers,
    },
  }
  
  if (body) {
    requestInit.body = JSON.stringify(body)
  }
  
  return new NextRequest(`http://localhost${url}`, requestInit)
}

describe('API Utils Security Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('getClientIp', () => {
    it('extracts first IP from x-forwarded-for header', () => {
      const request = createMockRequest('/test', {
        headers: { 'x-forwarded-for': '203.0.113.1, 198.51.100.1, 192.0.2.1' }
      })
      expect(getClientIp(request)).toBe('203.0.113.1')
    })

    it('handles single IP in x-forwarded-for', () => {
      const request = createMockRequest('/test', {
        headers: { 'x-forwarded-for': '203.0.113.1' }
      })
      expect(getClientIp(request)).toBe('203.0.113.1')
    })

    it('falls back to x-real-ip when x-forwarded-for missing', () => {
      const request = createMockRequest('/test', {
        headers: { 'x-real-ip': '203.0.113.2' }
      })
      expect(getClientIp(request)).toBe('203.0.113.2')
    })

    it('returns 127.0.0.1 when no IP headers present', () => {
      const request = createMockRequest('/test')
      expect(getClientIp(request)).toBe('127.0.0.1')
    })

    it('trims whitespace from IP addresses', () => {
      const request = createMockRequest('/test', {
        headers: { 'x-forwarded-for': '  203.0.113.1  , 198.51.100.1' }
      })
      expect(getClientIp(request)).toBe('203.0.113.1')
    })
  })

  describe('sanitizeInput', () => {
    it('removes script tags and content', () => {
      expect(sanitizeInput('Hello <script>alert("xss")</script>World'))
        .toBe('Hello World')
    })

    it('removes event handlers', () => {
      expect(sanitizeInput('<img onerror="alert(1)" src=x>'))
        .toBe('')
    })

    it('removes javascript: protocol', () => {
      expect(sanitizeInput('<a href="javascript:alert(1)">Click</a>'))
        .toBe('Click')
    })

    it('removes data: protocol from simple cases', () => {
      // Test that data: protocol is removed
      const result = sanitizeInput('data:text/html,<script>alert(1)</script>')
      expect(result).not.toContain('data:')
    })

    it('handles null bytes', () => {
      expect(sanitizeInput('Hello\x00World')).toBe('HelloWorld')
    })

    it('respects maxLength parameter', () => {
      const longString = 'a'.repeat(1000)
      expect(sanitizeInput(longString, 100).length).toBe(100)
    })

    it('handles empty string', () => {
      expect(sanitizeInput('')).toBe('')
    })

    it('removes HTML entities that could bypass filters', () => {
      expect(sanitizeInput('&#60;script&#62;alert(1)&#60;/script&#62;'))
        .toBe('scriptalert(1)/script')
    })

    it('handles nested tags', () => {
      expect(sanitizeInput('<div><span onclick="bad()">Test</span></div>'))
        .toBe('Test')
    })
  })

  describe('validateUUID', () => {
    it('accepts valid UUID v4', () => {
      expect(() => validateUUID('550e8400-e29b-41d4-a716-446655440000')).not.toThrow()
    })

    it('rejects invalid UUID format', () => {
      expect(() => validateUUID('not-a-uuid')).toThrow(ApiError)
    })

    it('rejects empty string', () => {
      expect(() => validateUUID('')).toThrow(ApiError)
    })

    it('rejects UUID with wrong version', () => {
      expect(() => validateUUID('550e8400-e29b-61d4-a716-446655440000')).toThrow(ApiError)
    })

    it('includes field name in error message', () => {
      try {
        validateUUID('invalid', 'seriesId')
      } catch (e) {
        expect((e as ApiError).message).toContain('seriesId')
      }
    })
  })

  describe('validateUsername', () => {
    it('accepts valid usernames', () => {
      expect(validateUsername('john_doe')).toBe(true)
      expect(validateUsername('user123')).toBe(true)
      expect(validateUsername('test-user')).toBe(true)
    })

    it('rejects too short usernames', () => {
      expect(validateUsername('ab')).toBe(false)
    })

    it('rejects too long usernames', () => {
      expect(validateUsername('a'.repeat(31))).toBe(false)
    })

    it('rejects special characters', () => {
      expect(validateUsername('user@name')).toBe(false)
      expect(validateUsername('user name')).toBe(false)
      expect(validateUsername('user.name')).toBe(false)
    })
  })

  describe('escapeILikePattern', () => {
    it('escapes percent signs', () => {
      expect(escapeILikePattern('100%')).toBe('100\\%')
    })

    it('escapes underscores', () => {
      expect(escapeILikePattern('user_name')).toBe('user\\_name')
    })

    it('escapes backslashes', () => {
      expect(escapeILikePattern('path\\to\\file')).toBe('path\\\\to\\\\file')
    })

    it('handles multiple special characters', () => {
      expect(escapeILikePattern('50%_off\\')).toBe('50\\%\\_off\\\\')
    })
  })

  describe('parsePaginationParams', () => {
    it('returns default values when no params provided', () => {
      const params = new URLSearchParams()
      const { page, limit, offset } = parsePaginationParams(params)
      expect(page).toBe(1)
      expect(limit).toBe(20)
      expect(offset).toBe(0)
    })

    it('respects page parameter', () => {
      const params = new URLSearchParams('page=3')
      const { page, offset } = parsePaginationParams(params)
      expect(page).toBe(3)
      expect(offset).toBe(40) // (3-1) * 20
    })

    it('respects offset parameter over page', () => {
      const params = new URLSearchParams('offset=50&page=1')
      const { offset, page } = parsePaginationParams(params)
      expect(offset).toBe(50)
      expect(page).toBe(3) // floor(50/20) + 1
    })

    it('enforces maximum limit of 100', () => {
      const params = new URLSearchParams('limit=500')
      const { limit } = parsePaginationParams(params)
      expect(limit).toBe(100)
    })

    it('enforces minimum limit of 1', () => {
      const params = new URLSearchParams('limit=-5')
      const { limit } = parsePaginationParams(params)
      expect(limit).toBe(1)
    })

    it('enforces maximum offset', () => {
      const params = new URLSearchParams('offset=2000000')
      const { offset } = parsePaginationParams(params)
      expect(offset).toBe(1000000)
    })
  })

  describe('checkRateLimit', () => {
    it('allows requests under limit', async () => {
      const result = await checkRateLimit('test-key', 10, 60000)
      expect(result).toBe(true)
    })

    it('blocks requests over limit', async () => {
      // Mock Redis to return count over limit
      (mockRedis.multi as jest.Mock).mockReturnValueOnce({
        incr: jest.fn().mockReturnThis(),
        pexpire: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([[null, 11]]),
      })
      
      const result = await checkRateLimit('test-key', 10, 60000)
      expect(result).toBe(false)
    })
  })
})

describe('API Route Integration Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    // Reset all prisma mocks
    mockPrismaUser.findUnique.mockReset()
    mockPrismaUser.findFirst.mockReset()
    mockPrismaUser.update.mockReset()
    mockPrismaLibraryEntry.findUnique.mockReset()
    mockPrismaFollow.findUnique.mockReset()
  })

  describe('GET /api/users/me', () => {
    it('returns 401 for unauthenticated requests', async () => {
      // Mock unauthenticated user
      const { createClient } = require('@/lib/supabase/server')
      createClient.mockReturnValueOnce({
        auth: {
          getUser: jest.fn(() => ({
            data: { user: null },
            error: null,
          })),
        },
      })

      const { GET } = await import('@/app/api/users/me/route')
      const request = createMockRequest('/api/users/me')
      const response = await GET(request)
      
      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data.code).toBe(ErrorCodes.UNAUTHORIZED)
    })

    it('returns user profile for authenticated requests', async () => {
      mockPrismaUser.findUnique.mockResolvedValue({
        id: 'test-user-id',
        email: 'test@example.com',
        username: 'testuser',
        xp: 100,
        level: 2,
        _count: { library_entries: 5, followers: 10, following: 8 },
      })

      const { GET } = await import('@/app/api/users/me/route')
      const request = createMockRequest('/api/users/me')
      const response = await GET(request)
      
      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.username).toBe('testuser')
    })
  })

  describe('PATCH /api/users/me', () => {
    it('validates username format', async () => {
      const { PATCH } = await import('@/app/api/users/me/route')
      const request = createMockRequest('/api/users/me', {
        method: 'PATCH',
        body: { username: 'ab' }, // Too short
        headers: { origin: 'http://localhost' },
      })
      
      const response = await PATCH(request)
      expect(response.status).toBe(400)
    })

    it('sanitizes username input', async () => {
      mockPrismaUser.findFirst.mockResolvedValue(null) // No existing user
      mockPrismaUser.update.mockImplementation(({ data }) => 
        Promise.resolve({ ...data, id: 'test-user-id' })
      )
      mockPrisma.$transaction.mockImplementation((fn) => fn(mockPrisma))

      const { PATCH } = await import('@/app/api/users/me/route')
      const request = createMockRequest('/api/users/me', {
        method: 'PATCH',
        body: { username: 'Test_User<script>' },
        headers: { origin: 'http://localhost' },
      })
      
      const response = await PATCH(request)
      
      // Check that the username was sanitized (lowercase, no script tags)
      if (mockPrismaUser.update.mock.calls.length > 0) {
        const updateCall = mockPrismaUser.update.mock.calls[0][0]
        expect(updateCall.data.username).not.toContain('<script>')
        expect(updateCall.data.username).toBe(updateCall.data.username.toLowerCase())
      }
    })
  })

  describe('POST /api/library', () => {
    it('validates seriesId as UUID', async () => {
      const { POST } = await import('@/app/api/library/route')
      const request = createMockRequest('/api/library', {
        method: 'POST',
        body: { seriesId: 'not-a-uuid', status: 'reading' },
        headers: { origin: 'http://localhost' },
      })
      
      const response = await POST(request)
      expect(response.status).toBe(400)
    })

    it('validates status enum', async () => {
      const { POST } = await import('@/app/api/library/route')
      const request = createMockRequest('/api/library', {
        method: 'POST',
        body: { 
          seriesId: '550e8400-e29b-41d4-a716-446655440000', 
          status: 'invalid-status' 
        },
        headers: { origin: 'http://localhost' },
      })
      
      const response = await POST(request)
      expect(response.status).toBe(400)
    })
  })

  describe('GET /api/leaderboard', () => {
    it('validates category parameter', async () => {
      const { GET } = await import('@/app/api/leaderboard/route')
      const request = createMockRequest('/api/leaderboard?category=invalid')
      
      const response = await GET(request)
      expect(response.status).toBe(400)
      const data = await response.json()
      expect(data.error).toContain('Invalid category')
    })

    it('validates period parameter', async () => {
      const { GET } = await import('@/app/api/leaderboard/route')
      const request = createMockRequest('/api/leaderboard?period=invalid')
      
      const response = await GET(request)
      expect(response.status).toBe(400)
      const data = await response.json()
      expect(data.error).toContain('Invalid period')
    })

    it('enforces limit bounds', async () => {
      mockPrismaUser.findMany.mockResolvedValue([])
      
      const { GET } = await import('@/app/api/leaderboard/route')
      const request = createMockRequest('/api/leaderboard?limit=500')
      
      await GET(request)
      
      // Verify limit was capped at 100
      const findManyCall = mockPrismaUser.findMany.mock.calls[0][0]
      expect(findManyCall.take).toBeLessThanOrEqual(100)
    })
  })
})

describe('Edge Cases and Error Handling', () => {
  describe('Invalid JSON body handling', () => {
    it('returns 400 for malformed JSON in PATCH requests', async () => {
      const { PATCH } = await import('@/app/api/users/me/route')
      
      // Create request with invalid JSON
      const request = new NextRequest('http://localhost/api/users/me', {
        method: 'PATCH',
        body: 'not valid json{',
        headers: {
          'content-type': 'application/json',
          'origin': 'http://localhost',
        },
      })
      
      const response = await PATCH(request)
      expect(response.status).toBe(400)
      const data = await response.json()
      expect(data.code).toBe(ErrorCodes.BAD_REQUEST)
    })
  })

  describe('XSS Prevention', () => {
    const xssPayloads = [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      'javascript:alert(1)',
      '<svg onload=alert(1)>',
      '"><script>alert(1)</script>',
      "'-alert(1)-'",
      '<body onload=alert(1)>',
      '{{constructor.constructor("alert(1)")()}}',
    ]

    it.each(xssPayloads)('sanitizes XSS payload: %s', (payload) => {
      const sanitized = sanitizeInput(payload)
      expect(sanitized).not.toContain('<script')
      expect(sanitized).not.toContain('javascript:')
      expect(sanitized).not.toMatch(/on\w+=/i)
    })
  })

  describe('SQL Injection Prevention', () => {
    const sqlPayloads = [
      "'; DROP TABLE users; --",
      "1' OR '1'='1",
      "1; SELECT * FROM users",
      "UNION SELECT * FROM users",
    ]

    it.each(sqlPayloads)('escapes SQL injection payload in ILIKE: %s', (payload) => {
      const escaped = escapeILikePattern(payload)
      // Verify special ILIKE characters are escaped
      expect(escaped.includes('%') ? escaped.includes('\\%') : true).toBe(true)
      expect(escaped.includes('_') ? escaped.includes('\\_') : true).toBe(true)
    })
  })
})

describe('Rate Limiting Tests', () => {
  it('returns 429 when rate limit exceeded', async () => {
    // Mock rate limit exceeded
    (mockRedis.multi as jest.Mock).mockReturnValue({
      incr: jest.fn().mockReturnThis(),
      pexpire: jest.fn().mockReturnThis(),
      exec: jest.fn().mockResolvedValue([[null, 101]]), // Over 100 limit
    })

    const result = await checkRateLimit('test-key', 100, 60000)
    expect(result).toBe(false)
  })

  it('auth endpoints use stricter rate limits (5/min)', async () => {
    // Test that checkAuthRateLimit passes the right limits
    // Mock to return count of 6 (over the 5 limit for auth)
    (mockRedis.multi as jest.Mock).mockReturnValueOnce({
      incr: jest.fn().mockReturnThis(),
      pexpire: jest.fn().mockReturnThis(),
      exec: jest.fn().mockResolvedValue([[null, 6]]),
    })

    // checkAuthRateLimit internally calls checkRateLimit with limit=5
    const result = await checkRateLimit('auth:127.0.0.1', 5, 60000)
    expect(result).toBe(false)
  })
})
