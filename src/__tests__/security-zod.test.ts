import { z } from 'zod'

const UpdateProfileSchema = z.object({
  username: z.string().min(3).max(20).regex(/^[a-z0-9_]+$/i, "Username can only contain letters, numbers, and underscores").optional(),
  bio: z.string().max(500).optional(),
  avatar_url: z.string().url().optional().or(z.literal("")),
  privacy_settings: z.object({
    library_public: z.boolean().optional(),
    activity_public: z.boolean().optional(),
    followers_public: z.boolean().optional(),
    following_public: z.boolean().optional(),
  }).optional(),
})

const LibraryQuerySchema = z.object({
  q: z.string().optional(),
  status: z.string().optional(),
  sort: z.enum(['updated', 'title', 'rating', 'added']).default('updated'),
  limit: z.coerce.number().min(1).max(200).default(100),
  offset: z.coerce.number().min(0).default(0),
})

describe('Zod Validation Security Tests', () => {
  describe('UpdateProfileSchema', () => {
    it('should block too short usernames', () => {
      const result = UpdateProfileSchema.safeParse({ username: 'ab' })
      expect(result.success).toBe(false)
    })

    it('should block too long usernames', () => {
      const result = UpdateProfileSchema.safeParse({ username: 'a'.repeat(21) })
      expect(result.success).toBe(false)
    })

    it('should block invalid characters in username', () => {
      const result = UpdateProfileSchema.safeParse({ username: 'user!name' })
      expect(result.success).toBe(false)
    })

    it('should allow extra fields in privacy_settings (no strict)', () => {
      const result = UpdateProfileSchema.safeParse({ 
        privacy_settings: { 
          library_public: true, 
          unknown_field: true 
        } 
      })
      expect(result.success).toBe(true)
    })

    it('should validate URLs for avatar_url', () => {
      const result = UpdateProfileSchema.safeParse({ avatar_url: 'not-a-url' })
      expect(result.success).toBe(false)
      expect(UpdateProfileSchema.safeParse({ avatar_url: 'https://example.com/img.png' }).success).toBe(true)
      expect(UpdateProfileSchema.safeParse({ avatar_url: '' }).success).toBe(true)
    })
  })

  describe('LibraryQuerySchema', () => {
    it('should coerce strings to numbers for limit/offset', () => {
      const result = LibraryQuerySchema.safeParse({ limit: '50', offset: '20' })
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.limit).toBe(50)
        expect(result.data.offset).toBe(20)
      }
    })

    it('should enforce min/max for limit', () => {
      expect(LibraryQuerySchema.safeParse({ limit: '0' }).success).toBe(false)
      expect(LibraryQuerySchema.safeParse({ limit: '201' }).success).toBe(false)
    })

    it('should validate sort enum', () => {
      expect(LibraryQuerySchema.safeParse({ sort: 'invalid' }).success).toBe(false)
      expect(LibraryQuerySchema.safeParse({ sort: 'title' }).success).toBe(true)
    })
  })
})
