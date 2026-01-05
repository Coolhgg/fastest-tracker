import { ApiError, validateRequired, validateUUID, parsePaginationParams, sanitizeInput } from '@/lib/api-utils'

describe('API Utils', () => {
  describe('ApiError', () => {
    it('should create error with default status code', () => {
      const error = new ApiError('Test error')
      expect(error.message).toBe('Test error')
      expect(error.statusCode).toBe(500)
      expect(error.name).toBe('ApiError')
    })

    it('should create error with custom status code', () => {
      const error = new ApiError('Not found', 404, 'NOT_FOUND')
      expect(error.statusCode).toBe(404)
      expect(error.code).toBe('NOT_FOUND')
    })

    it('should extend Error class', () => {
      const error = new ApiError('Test')
      expect(error).toBeInstanceOf(Error)
    })
  })

  describe('sanitizeInput', () => {
    it('should trim whitespace', () => {
      expect(sanitizeInput('  hello  ')).toBe('hello')
    })

    it('should truncate long strings', () => {
      const longString = 'a'.repeat(15000)
      expect(sanitizeInput(longString).length).toBe(10000)
    })

    it('should handle empty strings', () => {
      expect(sanitizeInput('')).toBe('')
    })
  })

  describe('validateRequired', () => {
    it('should pass when all fields present', () => {
      expect(() => {
        validateRequired({ name: 'test', email: 'test@test.com' }, ['name', 'email'])
      }).not.toThrow()
    })

    it('should throw when fields missing', () => {
      expect(() => {
        validateRequired({ name: 'test' }, ['name', 'email'])
      }).toThrow(ApiError)
    })

    it('should list missing fields in error', () => {
      expect(() => {
        validateRequired({}, ['name', 'email'])
      }).toThrow('Missing required fields: name, email')
    })
  })

  describe('validateUUID', () => {
    it('should pass for valid UUID', () => {
      expect(() => {
        validateUUID('550e8400-e29b-41d4-a716-446655440000')
      }).not.toThrow()
    })

    it('should throw for invalid UUID', () => {
      expect(() => {
        validateUUID('invalid-uuid')
      }).toThrow(ApiError)
    })

    it('should include field name in error', () => {
      expect(() => {
        validateUUID('invalid', 'userId')
      }).toThrow('Invalid userId format')
    })
  })

  describe('parsePaginationParams', () => {
    it('should return defaults when no params', () => {
      const params = new URLSearchParams()
      const result = parsePaginationParams(params)
      
      expect(result.page).toBe(1)
      expect(result.limit).toBe(20)
      expect(result.offset).toBe(0)
    })

    it('should parse page and limit', () => {
      const params = new URLSearchParams({ page: '3', limit: '50' })
      const result = parsePaginationParams(params)
      
      expect(result.page).toBe(3)
      expect(result.limit).toBe(50)
      expect(result.offset).toBe(100)
    })

    it('should cap limit at 100', () => {
      const params = new URLSearchParams({ limit: '500' })
      const result = parsePaginationParams(params)
      
      expect(result.limit).toBe(100)
    })

    it('should ensure minimum page is 1', () => {
      const params = new URLSearchParams({ page: '-5' })
      const result = parsePaginationParams(params)
      
      expect(result.page).toBe(1)
    })

    it('should calculate page from offset', () => {
      const params = new URLSearchParams({ offset: '40', limit: '20' })
      const result = parsePaginationParams(params)
      
      expect(result.page).toBe(3)
    })
  })
})
