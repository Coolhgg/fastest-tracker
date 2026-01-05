import { sanitizeInput, parsePaginationParams, htmlEncode } from '../lib/api-utils'

describe('Security & Utility Fixes', () => {
  describe('sanitizeInput', () => {
    it('should remove HTML tags', () => {
      expect(sanitizeInput('<script>alert("xss")</script>test')).not.toContain('<script>')
      expect(sanitizeInput('<img src=x onerror=alert(1)>')).not.toContain('<img')
    })

    it('should remove dangerous protocols', () => {
      expect(sanitizeInput('javascript:alert(1)')).not.toContain('javascript:')
      expect(sanitizeInput('data:text/html,<script>alert(1)</script>')).not.toContain('data:')
    })

    it('should remove event handlers and dangerous attributes', () => {
      expect(sanitizeInput('click here onclick=alert(1)')).not.toContain('onclick=')
      expect(sanitizeInput('style=color:red')).not.toContain('style=')
    })

    it('should respect maxLength after sanitization', () => {
      const longInput = 'a'.repeat(100) + '<script>' + 'b'.repeat(100)
      const result = sanitizeInput(longInput, 50)
      expect(result.length).toBe(50)
      expect(result).not.toContain('<script>')
    })
  })

  describe('parsePaginationParams', () => {
    it('should calculate page from offset correctly', () => {
      const params = new URLSearchParams('offset=20&limit=10')
      const result = parsePaginationParams(params)
      expect(result.page).toBe(3)
      expect(result.limit).toBe(10)
      expect(result.offset).toBe(20)
    })

    it('should calculate offset from page correctly', () => {
      const params = new URLSearchParams('page=3&limit=10')
      const result = parsePaginationParams(params)
      expect(result.page).toBe(3)
      expect(result.limit).toBe(10)
      expect(result.offset).toBe(20)
    })

    it('should handle zero offset', () => {
      const params = new URLSearchParams('offset=0&limit=20')
      const result = parsePaginationParams(params)
      expect(result.page).toBe(1)
      expect(result.offset).toBe(0)
    })

    it('should handle missing params with defaults', () => {
      const params = new URLSearchParams('')
      const result = parsePaginationParams(params)
      expect(result.page).toBe(1)
      expect(result.limit).toBe(20)
      expect(result.offset).toBe(0)
    })
  })

  describe('htmlEncode', () => {
    it('should encode special characters including slash', () => {
      expect(htmlEncode('<script src="/test.js">')).toBe('&lt;script src=&quot;&#x2F;test.js&quot;&gt;')
    })
  })
})
