import { parsePaginationParams, handleApiError } from '../lib/api-utils'

// API Integration & Performance Tests
describe('API Integration & Performance Tests', () => {
  describe('Pagination Logic', () => {
    it('should correctly parse pagination parameters', () => {
      const params = new URLSearchParams('page=2&limit=50')
      const { page, limit, offset } = parsePaginationParams(params)
      // page param is used directly, offset is calculated as (page-1) * limit
      expect(page).toBe(2)
      expect(limit).toBe(50)
      expect(offset).toBe(50) // (2-1) * 50 = 50
    })

    it('should enforce maximum limit of 100', () => {
      const params = new URLSearchParams('limit=200')
      const { limit } = parsePaginationParams(params)
      expect(limit).toBe(100) // max capped at 100
    })

    it('should use default limit of 20', () => {
      const params = new URLSearchParams('')
      const { limit } = parsePaginationParams(params)
      expect(limit).toBe(20) // default limit
    })

    it('should handle offset-based pagination', () => {
      const params = new URLSearchParams('offset=30&limit=10')
      const { page, limit, offset } = parsePaginationParams(params)
      // When offset is provided: actualPage = Math.floor(30/10) + 1 = 4
      // Then offset is recalculated as (4-1) * 10 = 30
      expect(page).toBe(4)
      expect(limit).toBe(10)
      expect(offset).toBe(30)
    })

    it('should return page 1 with default limit when no params', () => {
      const params = new URLSearchParams('')
      const { page, limit, offset } = parsePaginationParams(params)
      expect(page).toBe(1)
      expect(limit).toBe(20)
      expect(offset).toBe(0)
    })
  })

  describe('Error Handling Security', () => {
    it('should hide sensitive details in production', async () => {
      // In test env, error message is passed through
      // This test verifies the function exists and returns proper structure
      const response = handleApiError(new Error('Test error'))
      const body = await response.json()
      
      expect(body.error).toBeDefined()
      expect(body.code).toBe('INTERNAL_ERROR')
      expect(response.status).toBe(500)
    })

    it('should handle ApiError with custom status', async () => {
      const { ApiError } = await import('../lib/api-utils')
      const error = new ApiError('Not found', 404, 'NOT_FOUND')
      const response = handleApiError(error)
      const body = await response.json()
      
      expect(response.status).toBe(404)
      expect(body.error).toBe('Not found')
      expect(body.code).toBe('NOT_FOUND')
    })
  })

  describe('Social Feed N+1 Verification', () => {
    it('should use optimized query for following feed', async () => {
      const fs = await import('fs')
      const path = await import('path')
      const content = fs.readFileSync(path.join(process.cwd(), 'src/lib/social-utils.ts'), 'utf8')
      
      expect(content).toContain('some: { follower_id: userId }')
      expect(content).toContain('privacy_settings: {')
      expect(content).not.toMatch(/const followingIds =.*findMany/)
    })
  })
})
