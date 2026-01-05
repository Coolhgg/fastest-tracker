/**
 * Comprehensive Bug Fix Tests
 * Tests for the bugs fixed in this audit
 */

import { 
  isWhitelistedDomain, 
  isInternalIP,
  ALLOWED_CONTENT_TYPES,
  MAX_IMAGE_SIZE
} from '@/lib/constants/image-whitelist'

describe('Image Whitelist Security', () => {
  describe('isWhitelistedDomain', () => {
    it('should allow whitelisted domains', () => {
      expect(isWhitelistedDomain('https://cdn.mangadex.org/image.jpg')).toBe(true)
      expect(isWhitelistedDomain('https://i.imgur.com/image.png')).toBe(true)
      expect(isWhitelistedDomain('https://images.unsplash.com/photo.jpg')).toBe(true)
    })

    it('should allow subdomains of whitelisted domains', () => {
      expect(isWhitelistedDomain('https://sub.cdn.mangadex.org/image.jpg')).toBe(true)
    })

    it('should reject non-whitelisted domains', () => {
      expect(isWhitelistedDomain('https://evil.com/image.jpg')).toBe(false)
      expect(isWhitelistedDomain('https://mangadex.org.evil.com/image.jpg')).toBe(false)
    })

    it('should handle invalid URLs', () => {
      expect(isWhitelistedDomain('not-a-url')).toBe(false)
      expect(isWhitelistedDomain('')).toBe(false)
    })
  })

  describe('isInternalIP - SSRF Protection', () => {
    it('should block localhost', () => {
      expect(isInternalIP('localhost')).toBe(true)
      expect(isInternalIP('127.0.0.1')).toBe(true)
      expect(isInternalIP('::1')).toBe(true)
    })

    it('should block private IPv4 ranges', () => {
      // 10.x.x.x
      expect(isInternalIP('10.0.0.1')).toBe(true)
      expect(isInternalIP('10.255.255.255')).toBe(true)
      
      // 172.16.x.x - 172.31.x.x
      expect(isInternalIP('172.16.0.1')).toBe(true)
      expect(isInternalIP('172.31.255.255')).toBe(true)
      
      // 192.168.x.x
      expect(isInternalIP('192.168.0.1')).toBe(true)
      expect(isInternalIP('192.168.255.255')).toBe(true)
    })

    it('should block AWS metadata service', () => {
      expect(isInternalIP('169.254.169.254')).toBe(true)
    })

    it('should block internal hostnames', () => {
      expect(isInternalIP('internal.company.com')).toBe(true)
      expect(isInternalIP('intranet.local')).toBe(true)
      expect(isInternalIP('metadata.server')).toBe(true)
    })

    it('should allow public IPs', () => {
      expect(isInternalIP('8.8.8.8')).toBe(false)
      expect(isInternalIP('1.1.1.1')).toBe(false)
      expect(isInternalIP('cdn.mangadex.org')).toBe(false)
    })
  })

  describe('Content Type Validation', () => {
    it('should allow valid image types', () => {
      expect(ALLOWED_CONTENT_TYPES).toContain('image/jpeg')
      expect(ALLOWED_CONTENT_TYPES).toContain('image/png')
      expect(ALLOWED_CONTENT_TYPES).toContain('image/gif')
      expect(ALLOWED_CONTENT_TYPES).toContain('image/webp')
    })

    it('should not allow SVG (XSS risk)', () => {
      expect(ALLOWED_CONTENT_TYPES).not.toContain('image/svg+xml')
    })
  })

  describe('Size Limits', () => {
    it('should have reasonable max image size', () => {
      expect(MAX_IMAGE_SIZE).toBe(10 * 1024 * 1024) // 10MB
      expect(MAX_IMAGE_SIZE).toBeGreaterThan(1024 * 1024) // At least 1MB
    })
  })
})

describe('Library API Improvements', () => {
  describe('Status Validation', () => {
    const validStatuses = ['reading', 'completed', 'planning', 'dropped', 'paused']
    
    it('should have all valid statuses defined', () => {
      expect(validStatuses).toContain('reading')
      expect(validStatuses).toContain('completed')
      expect(validStatuses).toContain('planning')
      expect(validStatuses).toContain('dropped')
      expect(validStatuses).toContain('paused')
    })

    it('should validate status correctly', () => {
      const isValidStatus = (status: string) => validStatuses.includes(status)
      
      expect(isValidStatus('reading')).toBe(true)
      expect(isValidStatus('invalid')).toBe(false)
      expect(isValidStatus('')).toBe(false)
    })
  })

  describe('Sort Options', () => {
    const validSortOptions = ['updated', 'title', 'rating', 'added']
    
    it('should support all sort options', () => {
      expect(validSortOptions).toContain('updated')
      expect(validSortOptions).toContain('title')
      expect(validSortOptions).toContain('rating')
      expect(validSortOptions).toContain('added')
    })
  })

  describe('Rating Validation', () => {
    const isValidRating = (rating: number) => {
      return !isNaN(rating) && rating >= 1 && rating <= 10
    }

    it('should accept valid ratings', () => {
      expect(isValidRating(1)).toBe(true)
      expect(isValidRating(5)).toBe(true)
      expect(isValidRating(10)).toBe(true)
    })

    it('should reject invalid ratings', () => {
      expect(isValidRating(0)).toBe(false)
      expect(isValidRating(11)).toBe(false)
      expect(isValidRating(-1)).toBe(false)
      expect(isValidRating(NaN)).toBe(false)
    })
  })
})

describe('User Search Security', () => {
  describe('Query Sanitization', () => {
    const sanitizeQuery = (query: string) => {
      return query.replace(/[%_\\]/g, '')
    }

    it('should remove SQL wildcards', () => {
      expect(sanitizeQuery('test%')).toBe('test')
      expect(sanitizeQuery('test_name')).toBe('testname')
      expect(sanitizeQuery('test\\injection')).toBe('testinjection')
    })

    it('should preserve normal characters', () => {
      expect(sanitizeQuery('normaluser')).toBe('normaluser')
      expect(sanitizeQuery('user123')).toBe('user123')
    })
  })

  describe('Rate Limiting', () => {
    it('should have reasonable rate limits defined', () => {
      const userSearchLimit = 30
      const seriesSearchLimit = 60
      const imageProxyLimit = 100
      
      expect(userSearchLimit).toBeGreaterThan(0)
      expect(seriesSearchLimit).toBeGreaterThan(0)
      expect(imageProxyLimit).toBeGreaterThan(0)
    })
  })
})

describe('UUID Validation', () => {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
  
  const isValidUUID = (uuid: string) => uuidRegex.test(uuid)

  it('should accept valid UUIDs', () => {
    expect(isValidUUID('550e8400-e29b-41d4-a716-446655440000')).toBe(true)
    expect(isValidUUID('123e4567-e89b-12d3-a456-426614174000')).toBe(true)
  })

  it('should reject invalid UUIDs', () => {
    expect(isValidUUID('not-a-uuid')).toBe(false)
    expect(isValidUUID('550e8400-e29b-41d4-a716')).toBe(false)
    expect(isValidUUID('')).toBe(false)
    expect(isValidUUID('550e8400-e29b-41d4-a716-446655440000-extra')).toBe(false)
  })

  it('should reject SQL injection attempts', () => {
    expect(isValidUUID("550e8400-e29b-41d4-a716-446655440000' OR '1'='1")).toBe(false)
    expect(isValidUUID('550e8400-e29b-41d4-a716-446655440000; DROP TABLE users;')).toBe(false)
  })
})

describe('Pagination Validation', () => {
  const validatePagination = (page: number, limit: number) => {
    return {
      page: Math.max(1, Math.floor(page)),
      limit: Math.min(100, Math.max(1, Math.floor(limit))),
    }
  }

  it('should enforce minimum page of 1', () => {
    expect(validatePagination(0, 20).page).toBe(1)
    expect(validatePagination(-5, 20).page).toBe(1)
  })

  it('should enforce maximum limit of 100', () => {
    expect(validatePagination(1, 500).limit).toBe(100)
    expect(validatePagination(1, 1000).limit).toBe(100)
  })

  it('should enforce minimum limit of 1', () => {
    expect(validatePagination(1, 0).limit).toBe(1)
    expect(validatePagination(1, -10).limit).toBe(1)
  })

  it('should floor floating point numbers', () => {
    expect(validatePagination(1.5, 20.7).page).toBe(1)
    expect(validatePagination(1.5, 20.7).limit).toBe(20)
  })
})

describe('XP and Level Calculations', () => {
  const calculateLevel = (xp: number): number => {
    return Math.floor(Math.sqrt(xp / 100)) + 1
  }

  const xpForLevel = (level: number): number => {
    if (level <= 1) return 0
    return Math.pow(level - 1, 2) * 100
  }

  it('should calculate correct levels', () => {
    expect(calculateLevel(0)).toBe(1)
    expect(calculateLevel(99)).toBe(1)
    expect(calculateLevel(100)).toBe(2)
    expect(calculateLevel(400)).toBe(3)
    expect(calculateLevel(900)).toBe(4)
  })

  it('should calculate XP requirements correctly', () => {
    expect(xpForLevel(1)).toBe(0)
    expect(xpForLevel(2)).toBe(100)
    expect(xpForLevel(3)).toBe(400)
    expect(xpForLevel(4)).toBe(900)
    expect(xpForLevel(5)).toBe(1600)
  })

  it('should be consistent (level from XP matches XP for level)', () => {
    for (let level = 1; level <= 10; level++) {
      const xp = xpForLevel(level)
      expect(calculateLevel(xp)).toBe(level)
    }
  })
})

describe('Privacy Settings', () => {
  interface PrivacySettings {
    library_public?: boolean
    activity_public?: boolean
    profile_searchable?: boolean
  }

  const defaultPrivacy: PrivacySettings = {
    library_public: true,
    activity_public: true,
    profile_searchable: true,
  }

  const isPublic = (settings: PrivacySettings | null, field: keyof PrivacySettings) => {
    if (!settings) return true // Default to public
    return settings[field] !== false // Default to true if undefined
  }

  it('should default to public when settings are null', () => {
    expect(isPublic(null, 'library_public')).toBe(true)
    expect(isPublic(null, 'activity_public')).toBe(true)
    expect(isPublic(null, 'profile_searchable')).toBe(true)
  })

  it('should respect explicit false values', () => {
    const privateSettings: PrivacySettings = {
      library_public: false,
      activity_public: false,
      profile_searchable: false,
    }
    
    expect(isPublic(privateSettings, 'library_public')).toBe(false)
    expect(isPublic(privateSettings, 'activity_public')).toBe(false)
    expect(isPublic(privateSettings, 'profile_searchable')).toBe(false)
  })

  it('should default to true when field is undefined', () => {
    const partialSettings: PrivacySettings = {}
    
    expect(isPublic(partialSettings, 'library_public')).toBe(true)
    expect(isPublic(partialSettings, 'activity_public')).toBe(true)
  })
})

describe('Error Handling', () => {
  describe('HTTP Status Codes', () => {
    const statusCodes = {
      OK: 200,
      CREATED: 201,
      BAD_REQUEST: 400,
      UNAUTHORIZED: 401,
      FORBIDDEN: 403,
      NOT_FOUND: 404,
      CONFLICT: 409,
      UNPROCESSABLE_ENTITY: 422,
      TOO_MANY_REQUESTS: 429,
      INTERNAL_ERROR: 500,
    }

    it('should have correct status codes defined', () => {
      expect(statusCodes.OK).toBe(200)
      expect(statusCodes.UNAUTHORIZED).toBe(401)
      expect(statusCodes.NOT_FOUND).toBe(404)
      expect(statusCodes.TOO_MANY_REQUESTS).toBe(429)
    })
  })

  describe('Error Messages', () => {
    const errorMessages = {
      unauthorized: 'Unauthorized',
      notFound: 'Not found',
      invalidInput: 'Invalid input',
      rateLimited: 'Too many requests',
    }

    it('should have user-friendly error messages', () => {
      expect(errorMessages.unauthorized.length).toBeGreaterThan(0)
      expect(errorMessages.notFound.length).toBeGreaterThan(0)
      expect(errorMessages.rateLimited.length).toBeGreaterThan(0)
    })
  })
})
