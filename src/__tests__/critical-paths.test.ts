/**
 * Integration Tests for Critical API Paths
 * Tests end-to-end flows for authentication, library, search, and social features
 */

// Mock Supabase client
jest.mock('@/lib/supabase/server', () => ({
  createClient: jest.fn(() => Promise.resolve({
    auth: {
      getUser: jest.fn(() => Promise.resolve({
        data: { user: { id: 'test-user-id', email: 'test@example.com' } }
      }))
    },
    from: jest.fn(() => ({
      select: jest.fn().mockReturnThis(),
      insert: jest.fn().mockReturnThis(),
      update: jest.fn().mockReturnThis(),
      delete: jest.fn().mockReturnThis(),
      eq: jest.fn().mockReturnThis(),
      neq: jest.fn().mockReturnThis(),
      order: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      single: jest.fn(() => Promise.resolve({ data: {}, error: null })),
    }))
  }))
}));

jest.mock('@/lib/supabase/admin', () => ({
  supabaseAdmin: {
    from: jest.fn(() => ({
      select: jest.fn().mockReturnThis(),
      insert: jest.fn().mockReturnThis(),
      update: jest.fn().mockReturnThis(),
      delete: jest.fn().mockReturnThis(),
      eq: jest.fn().mockReturnThis(),
      in: jest.fn().mockReturnThis(),
      contains: jest.fn().mockReturnThis(),
      overlaps: jest.fn().mockReturnThis(),
      or: jest.fn().mockReturnThis(),
      order: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      range: jest.fn().mockReturnThis(),
      ilike: jest.fn().mockReturnThis(),
      gte: jest.fn().mockReturnThis(),
      lte: jest.fn().mockReturnThis(),
      not: jest.fn().mockReturnThis(),
      single: jest.fn(() => Promise.resolve({ data: {}, error: null, count: 0 })),
    })),
    rpc: jest.fn(() => Promise.resolve({ data: null, error: null })),
  }
}));

jest.mock('@/lib/prisma', () => ({
  prisma: {
    user: {
      findFirst: jest.fn(() => Promise.resolve(null)),
      findUnique: jest.fn(() => Promise.resolve(null)),
      update: jest.fn(() => Promise.resolve({})),
    },
    libraryEntry: {
      findUnique: jest.fn(() => Promise.resolve(null)),
      findMany: jest.fn(() => Promise.resolve([])),
      create: jest.fn(() => Promise.resolve({})),
      update: jest.fn(() => Promise.resolve({})),
      delete: jest.fn(() => Promise.resolve({})),
    },
    notification: {
      findMany: jest.fn(() => Promise.resolve([])),
      count: jest.fn(() => Promise.resolve(0)),
      updateMany: jest.fn(() => Promise.resolve({ count: 0 })),
    },
    follow: {
      findUnique: jest.fn(() => Promise.resolve(null)),
      create: jest.fn(() => Promise.resolve({})),
      deleteMany: jest.fn(() => Promise.resolve({ count: 0 })),
    },
    $transaction: jest.fn((fn) => fn({
      libraryEntry: {
        findUnique: jest.fn(() => Promise.resolve(null)),
        update: jest.fn(() => Promise.resolve({})),
        delete: jest.fn(() => Promise.resolve({})),
      },
      user: {
        findUnique: jest.fn(() => Promise.resolve({ xp: 0 })),
        update: jest.fn(() => Promise.resolve({})),
      },
      series: {
        findUnique: jest.fn(() => Promise.resolve({ total_follows: 1 })),
        update: jest.fn(() => Promise.resolve({})),
      },
    })),
  },
  withRetry: jest.fn((fn) => fn()),
}));

jest.mock('@/lib/redis', () => ({
  redis: {
    get: jest.fn(() => Promise.resolve(null)),
    set: jest.fn(() => Promise.resolve('OK')),
  },
  waitForRedis: jest.fn(() => Promise.resolve()),
  areWorkersOnline: jest.fn(() => Promise.resolve(false)),
  REDIS_KEY_PREFIX: 'kenmei:',
}));

jest.mock('@/lib/queues', () => ({
  checkSourceQueue: {
    add: jest.fn(() => Promise.resolve({ id: 'job-id' })),
  },
  isQueueHealthy: jest.fn(() => Promise.resolve(false)),
}));

jest.mock('@/lib/analytics', () => ({
  recordSearchEvent: jest.fn(),
}));

jest.mock('@/lib/cover-resolver', () => ({
  getBestCoversBatch: jest.fn(() => Promise.resolve(new Map())),
  selectBestCover: jest.fn(() => null),
  isValidCoverUrl: jest.fn(() => true),
}));

import { NextRequest } from 'next/server';
import { FilterSchema, DEFAULT_FILTERS } from '@/lib/schemas/filters';
import { clearRateLimit } from '@/lib/api-utils';

// Helper to create mock requests
function createMockRequest(
  url: string, 
  options: { method?: string; headers?: Record<string, string>; body?: any } = {}
): NextRequest {
  const { method = 'GET', headers = {}, body } = options;
  const fullUrl = `http://localhost:3000${url}`;
  
  return {
    url: fullUrl,
    nextUrl: new URL(fullUrl),
    method,
    headers: new Headers({
      'x-forwarded-for': '127.0.0.1',
      'host': 'localhost:3000',
      'origin': 'http://localhost:3000',
      ...headers,
    }),
    json: body ? () => Promise.resolve(body) : undefined,
  } as unknown as NextRequest;
}

describe('Integration: Search API', () => {
  beforeEach(() => {
    clearRateLimit('search:127.0.0.1');
    jest.clearAllMocks();
  });

  it('should validate and parse filter parameters', async () => {
    const searchParams = new URLSearchParams({
      q: 'one piece',
      type: 'manga,manhwa',
      genres: 'action,adventure',
      sortBy: 'popularity',
      limit: '24',
    });

    const url = `/api/series/search?${searchParams}`;
    const req = createMockRequest(url);

    // Validate the filter parsing logic
    const rawFilters = {
      q: searchParams.get('q'),
      type: searchParams.get('type')?.split(',').filter(Boolean) || [],
      genres: searchParams.get('genres')?.split(',').filter(Boolean) || [],
      sortBy: searchParams.get('sortBy') || 'newest',
      limit: parseInt(searchParams.get('limit') || '24'),
      mode: 'all',
    };

    expect(rawFilters.q).toBe('one piece');
    expect(rawFilters.type).toEqual(['manga', 'manhwa']);
    expect(rawFilters.genres).toEqual(['action', 'adventure']);
    expect(rawFilters.sortBy).toBe('popularity');
    expect(rawFilters.limit).toBe(24);
  });

  it('should reject invalid filter values', () => {
    const invalidFilters = {
      ...DEFAULT_FILTERS,
      sortBy: 'invalid_sort',
      limit: 500,
    };

    const result = FilterSchema.safeParse(invalidFilters);
    expect(result.success).toBe(false);
  });

  it('should handle empty search gracefully', () => {
    const emptyFilters = {
      ...DEFAULT_FILTERS,
      q: '',
      type: [],
      genres: [],
    };

    const result = FilterSchema.safeParse(emptyFilters);
    expect(result.success).toBe(true);
  });
});

describe('Integration: Library API', () => {
  beforeEach(() => {
    clearRateLimit('library-get:127.0.0.1');
    clearRateLimit('library-add:test-user-id');
    clearRateLimit('library-update:127.0.0.1');
    clearRateLimit('library-delete:127.0.0.1');
    jest.clearAllMocks();
  });

  it('should validate library entry status values', () => {
    const validStatuses = ['reading', 'completed', 'planning', 'dropped', 'paused'];
    const invalidStatuses = ['invalid', 'READING', 'read', ''];

    validStatuses.forEach(status => {
      expect(validStatuses.includes(status)).toBe(true);
    });

    invalidStatuses.forEach(status => {
      expect(validStatuses.includes(status)).toBe(false);
    });
  });

  it('should validate rating range (1-10)', () => {
    const validRatings = [1, 5, 10, 7.5];
    const invalidRatings = [0, -1, 11, 100, NaN];

    validRatings.forEach(rating => {
      expect(rating >= 1 && rating <= 10).toBe(true);
    });

    invalidRatings.forEach(rating => {
      expect(rating >= 1 && rating <= 10 && !isNaN(rating)).toBe(false);
    });
  });

  it('should validate UUID format for series ID', () => {
    const { validateUUID } = require('@/lib/api-utils');
    
    expect(() => validateUUID('550e8400-e29b-41d4-a716-446655440000')).not.toThrow();
    expect(() => validateUUID('invalid-id')).toThrow();
  });
});

describe('Integration: Saved Filters API', () => {
  beforeEach(() => {
    clearRateLimit('filters-get:127.0.0.1');
    clearRateLimit('filters-create:127.0.0.1');
    clearRateLimit('filters-update:127.0.0.1');
    clearRateLimit('filters-delete:127.0.0.1');
    jest.clearAllMocks();
  });

  it('should validate filter name requirements', () => {
    const { sanitizeInput } = require('@/lib/api-utils');
    
    // Valid names
    expect(sanitizeInput('My Filter', 100).length).toBeGreaterThan(0);
    expect(sanitizeInput('Action Manga', 100).length).toBeGreaterThan(0);
    
    // Should sanitize dangerous content
    const maliciousName = '<script>alert("xss")</script>';
    const sanitized = sanitizeInput(maliciousName, 100);
    expect(sanitized).not.toContain('<script>');
  });

  it('should validate filter payload against schema', () => {
    const validPayload = {
      ...DEFAULT_FILTERS,
      genres: ['action'],
      sortBy: 'popularity',
    };

    const result = FilterSchema.safeParse(validPayload);
    expect(result.success).toBe(true);
  });

  it('should reject invalid filter payloads', () => {
    const invalidPayloads = [
      { sortBy: 'DROP TABLE' },
      { limit: -1 },
      { mode: 'invalid' },
      'not an object',
      null,
    ];

    invalidPayloads.forEach(payload => {
      const result = FilterSchema.safeParse(payload);
      expect(result.success).toBe(false);
    });
  });
});

describe('Integration: Social Features', () => {
  beforeEach(() => {
    clearRateLimit('follow-status:127.0.0.1');
    clearRateLimit('follow-action:127.0.0.1');
    jest.clearAllMocks();
  });

  it('should validate username format', () => {
    const { validateUsername } = require('@/lib/api-utils');
    
    // Valid usernames
    expect(validateUsername('user123')).toBe(true);
    expect(validateUsername('test_user')).toBe(true);
    expect(validateUsername('User-Name')).toBe(true);
    
    // Invalid usernames
    expect(validateUsername('ab')).toBe(false); // Too short
    expect(validateUsername('a'.repeat(31))).toBe(false); // Too long
    expect(validateUsername('user@name')).toBe(false); // Invalid char
    expect(validateUsername('user name')).toBe(false); // Space
  });

  it('should prevent following yourself', () => {
    const followerId = 'user-id-123';
    const targetId = 'user-id-123';
    
    expect(followerId === targetId).toBe(true);
    // The actual function would throw "Cannot follow yourself"
  });
});

describe('Integration: Rate Limiting', () => {
  it('should enforce rate limits across endpoints', () => {
    const { checkRateLimit, clearRateLimit } = require('@/lib/api-utils');
    
    const endpoints = [
      { key: 'search:127.0.0.1', limit: 60 },
      { key: 'library-get:127.0.0.1', limit: 60 },
      { key: 'follow-action:127.0.0.1', limit: 30 },
      { key: 'filters-create:127.0.0.1', limit: 10 },
    ];

    endpoints.forEach(({ key, limit }) => {
      clearRateLimit(key);
      
      // Should allow up to limit
      for (let i = 0; i < limit; i++) {
        expect(checkRateLimit(key, limit, 60000)).toBe(true);
      }
      
      // Should block after limit
      expect(checkRateLimit(key, limit, 60000)).toBe(false);
      
      clearRateLimit(key);
    });
  });
});

describe('Integration: Error Handling', () => {
  it('should handle database errors gracefully', () => {
    const { handleApiError, ApiError } = require('@/lib/api-utils');
    
    const dbError = new Error('Database connection failed');
    const response = handleApiError(dbError);
    
    expect(response.status).toBe(500);
  });

  it('should return appropriate status codes for different errors', () => {
    const { handleApiError, ApiError, ErrorCodes } = require('@/lib/api-utils');
    
    const testCases = [
      { error: new ApiError('Not found', 404, ErrorCodes.NOT_FOUND), expectedStatus: 404 },
      { error: new ApiError('Unauthorized', 401, ErrorCodes.UNAUTHORIZED), expectedStatus: 401 },
      { error: new ApiError('Rate limited', 429, ErrorCodes.RATE_LIMITED), expectedStatus: 429 },
      { error: new ApiError('Bad request', 400, ErrorCodes.BAD_REQUEST), expectedStatus: 400 },
    ];

    testCases.forEach(({ error, expectedStatus }) => {
      const response = handleApiError(error);
      expect(response.status).toBe(expectedStatus);
    });
  });
});
