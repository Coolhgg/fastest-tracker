/**
 * Bug Bounty Security Tests
 * Tests for all security vulnerabilities discovered during audit
 */

import { 
  sanitizeInput, 
  escapeILikePattern, 
  validateUUID, 
  checkRateLimit,
  clearRateLimit,
  ApiError 
} from '@/lib/api-utils';
import { FilterSchema, DEFAULT_FILTERS } from '@/lib/schemas/filters';
import { 
  buildSeriesQuery, 
  encodeCursor, 
  decodeCursor, 
  getSortColumn 
} from '@/lib/api/search-query';
import { detectSearchIntent } from '@/lib/search-intent';

describe('Bug Bounty: Security Tests', () => {
  
  describe('SQL Injection Prevention', () => {
    
    it('should escape ILIKE special characters', () => {
      expect(escapeILikePattern('test%')).toBe('test\\%');
      expect(escapeILikePattern('test_')).toBe('test\\_');
      expect(escapeILikePattern('test\\')).toBe('test\\\\');
      expect(escapeILikePattern('%_%\\')).toBe('\\%\\_\\%\\\\');
    });

    it('should prevent SQL injection via search query', () => {
      const maliciousInputs = [
        "'; DROP TABLE series; --",
        "1' OR '1'='1",
        "test%'; DELETE FROM users; --",
        "test\"; SELECT * FROM users; --",
        "' UNION SELECT * FROM users --",
      ];

      maliciousInputs.forEach(input => {
        const sanitized = sanitizeInput(input);
        const escaped = escapeILikePattern(sanitized);
        
        // Should not contain unescaped dangerous characters
        expect(escaped).not.toMatch(/(?<!\\)['"]/);
        expect(escaped).not.toContain('--');
        expect(escaped).not.toMatch(/DROP|DELETE|UNION|SELECT/i);
      });
    });

    it('should handle unicode and special characters safely', () => {
      const unicodeInputs = [
        '日本語テスト',
        '🎮 Game Title',
        'Café Résumé',
        'test\u0000null',
        'test\r\nnewline',
      ];

      unicodeInputs.forEach(input => {
        const sanitized = sanitizeInput(input);
        expect(typeof sanitized).toBe('string');
        // Should not throw
        escapeILikePattern(sanitized);
      });
    });
  });

  describe('XSS Prevention', () => {
    
    it('should strip HTML tags from input', () => {
      expect(sanitizeInput('<script>alert("xss")</script>')).toBe('alert("xss")');
      expect(sanitizeInput('<img src=x onerror=alert(1)>')).toBe('');
      expect(sanitizeInput('<a href="javascript:alert(1)">click</a>')).toBe('click');
    });

    it('should remove dangerous protocols', () => {
      expect(sanitizeInput('javascript:alert(1)')).toBe('alert(1)');
      expect(sanitizeInput('data:text/html,<script>alert(1)</script>')).toBe('text/html,alert(1)');
      expect(sanitizeInput('vbscript:msgbox(1)')).toBe('msgbox(1)');
    });

    it('should remove event handlers', () => {
      expect(sanitizeInput('onclick=alert(1)')).toBe('alert(1)');
      expect(sanitizeInput('onload=evil()')).toBe('evil()');
      expect(sanitizeInput('onerror=hack()')).toBe('hack()');
    });

    it('should handle encoded XSS attempts', () => {
      // URL encoded
      const encoded = sanitizeInput('%3Cscript%3Ealert(1)%3C/script%3E');
      expect(encoded).not.toContain('<script>');
      
      // HTML entities should be stripped
      const entities = sanitizeInput('&#60;script&#62;');
      expect(entities).not.toContain('<');
    });
  });

  describe('Input Validation', () => {
    
    describe('UUID Validation', () => {
      it('should accept valid UUIDs', () => {
        const validUUIDs = [
          '550e8400-e29b-41d4-a716-446655440000',
          '6ba7b810-9dad-11d1-80b4-00c04fd430c8',
          'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        ];

        validUUIDs.forEach(uuid => {
          expect(() => validateUUID(uuid)).not.toThrow();
        });
      });

      it('should reject invalid UUIDs', () => {
        const invalidUUIDs = [
          'not-a-uuid',
          '550e8400-e29b-41d4-a716', // Too short
          '550e8400-e29b-41d4-a716-446655440000-extra', // Too long
          '550e8400-e29b-61d4-a716-446655440000', // Invalid version (6)
          '550e8400-e29b-41d4-c716-446655440000', // Invalid variant (c)
          '../../../etc/passwd', // Path traversal
          "'; DROP TABLE users; --", // SQL injection
        ];

        invalidUUIDs.forEach(uuid => {
          expect(() => validateUUID(uuid)).toThrow(ApiError);
        });
      });
    });

    describe('Filter Schema Validation', () => {
      it('should accept valid filters', () => {
        const result = FilterSchema.safeParse(DEFAULT_FILTERS);
        expect(result.success).toBe(true);
      });

      it('should reject invalid sortBy values', () => {
        const result = FilterSchema.safeParse({
          ...DEFAULT_FILTERS,
          sortBy: 'DROP TABLE series; --'
        });
        expect(result.success).toBe(false);
      });

      it('should enforce limit bounds', () => {
        const tooHigh = FilterSchema.safeParse({ ...DEFAULT_FILTERS, limit: 1000 });
        expect(tooHigh.success).toBe(false);

        const tooLow = FilterSchema.safeParse({ ...DEFAULT_FILTERS, limit: 0 });
        expect(tooLow.success).toBe(false);

        const valid = FilterSchema.safeParse({ ...DEFAULT_FILTERS, limit: 50 });
        expect(valid.success).toBe(true);
      });

      it('should validate mode enum', () => {
        const invalidMode = FilterSchema.safeParse({ ...DEFAULT_FILTERS, mode: 'invalid' });
        expect(invalidMode.success).toBe(false);

        const validAny = FilterSchema.safeParse({ ...DEFAULT_FILTERS, mode: 'any' });
        expect(validAny.success).toBe(true);

        const validAll = FilterSchema.safeParse({ ...DEFAULT_FILTERS, mode: 'all' });
        expect(validAll.success).toBe(true);
      });
    });
  });

  describe('Rate Limiting', () => {
    
    beforeEach(() => {
      clearRateLimit('test-key');
    });

    it('should allow requests within limit', () => {
      for (let i = 0; i < 5; i++) {
        expect(checkRateLimit('test-key', 5, 60000)).toBe(true);
      }
    });

    it('should block requests exceeding limit', () => {
      for (let i = 0; i < 5; i++) {
        checkRateLimit('test-key', 5, 60000);
      }
      expect(checkRateLimit('test-key', 5, 60000)).toBe(false);
    });

    it('should track different keys independently', () => {
      for (let i = 0; i < 5; i++) {
        checkRateLimit('key-a', 5, 60000);
      }
      expect(checkRateLimit('key-a', 5, 60000)).toBe(false);
      expect(checkRateLimit('key-b', 5, 60000)).toBe(true);
    });
  });

  describe('Cursor Pagination Security', () => {
    
    it('should encode and decode cursors correctly', () => {
      const cursor = encodeCursor('2024-01-01', '550e8400-e29b-41d4-a716-446655440000');
      const [value, id] = decodeCursor(cursor);
      
      expect(value).toBe('2024-01-01');
      expect(id).toBe('550e8400-e29b-41d4-a716-446655440000');
    });

    it('should handle null values in cursor', () => {
      const cursor = encodeCursor(null, '550e8400-e29b-41d4-a716-446655440000');
      const [value, id] = decodeCursor(cursor);
      
      expect(value).toBe('');
      expect(id).toBe('550e8400-e29b-41d4-a716-446655440000');
    });

    it('should reject tampered cursors', () => {
      expect(() => decodeCursor('invalid-base64!@#$')).toThrow();
      expect(() => decodeCursor('')).toThrow();
    });

    it('should handle cursors with special characters in values', () => {
      const cursor = encodeCursor('value|with|pipes', '550e8400-e29b-41d4-a716-446655440000');
      const [value, id] = decodeCursor(cursor);
      
      expect(value).toBe('value|with|pipes');
      expect(id).toBe('550e8400-e29b-41d4-a716-446655440000');
    });
  });

  describe('Search Intent Detection', () => {
    
    it('should detect partial titles for external search', () => {
      // "one piec" should trigger external search (PARTIAL_TITLE)
      const intent = detectSearchIntent('one piec', []);
      expect(intent).toBe('PARTIAL_TITLE');
    });

    it('should detect exact titles', () => {
      const mockResults = [{
        title: 'One Piece',
        alternative_titles: ['ワンピース']
      }];
      
      const intent = detectSearchIntent('one piece', mockResults);
      expect(intent).toBe('EXACT_TITLE');
    });

    it('should classify noise queries', () => {
      expect(detectSearchIntent('a', [])).toBe('NOISE');
      expect(detectSearchIntent('12', [])).toBe('NOISE');
      expect(detectSearchIntent('', [])).toBe('NOISE');
    });

    it('should detect keyword exploration', () => {
      const intent = detectSearchIntent('isekai fantasy', []);
      expect(intent).toBe('KEYWORD_EXPLORATION');
    });
  });

  describe('Sort Column Mapping', () => {
    
    it('should map all valid sort options', () => {
      expect(getSortColumn('newest')).toBe('created_at');
      expect(getSortColumn('updated')).toBe('last_chapter_date');
      expect(getSortColumn('popularity')).toBe('total_follows');
      expect(getSortColumn('follows')).toBe('total_follows');
      expect(getSortColumn('views')).toBe('total_views');
      expect(getSortColumn('score')).toBe('average_rating');
      expect(getSortColumn('chapters')).toBe('chapter_count');
      expect(getSortColumn('alpha')).toBe('title');
    });

    it('should default to created_at for unknown values', () => {
      expect(getSortColumn('invalid')).toBe('created_at');
      expect(getSortColumn('')).toBe('created_at');
      expect(getSortColumn('DROP TABLE')).toBe('created_at');
    });
  });
});

describe('Bug Bounty: Edge Cases', () => {
  
  describe('Empty and Null Handling', () => {
    
    it('should handle empty strings gracefully', () => {
      expect(sanitizeInput('')).toBe('');
      expect(escapeILikePattern('')).toBe('');
    });

    it('should handle whitespace-only strings', () => {
      expect(sanitizeInput('   ')).toBe('');
      expect(sanitizeInput('\t\n\r')).toBe('');
    });
  });

  describe('Length Limits', () => {
    
    it('should enforce maximum input length', () => {
      const longInput = 'a'.repeat(20000);
      const sanitized = sanitizeInput(longInput, 100);
      expect(sanitized.length).toBeLessThanOrEqual(100);
    });

    it('should handle exactly max length input', () => {
      const exactInput = 'a'.repeat(100);
      const sanitized = sanitizeInput(exactInput, 100);
      expect(sanitized.length).toBe(100);
    });
  });

  describe('Filter Combinations', () => {
    
    it('should accept complex filter combinations', () => {
      const complexFilters = {
        q: 'test query',
        type: ['manga', 'manhwa'],
        genres: ['action', 'adventure'],
        tags: ['isekai'],
        themes: [],
        contentWarnings: { include: [], exclude: ['gore'] },
        publicationStatus: ['ongoing'],
        contentRating: ['safe'],
        readableOn: [],
        languages: { translated: ['en'] },
        chapterCount: { min: 10, max: 100 },
        sortBy: 'popularity' as const,
        sortOrder: 'desc' as const,
        limit: 24,
        mode: 'all' as const,
      };

      const result = FilterSchema.safeParse(complexFilters);
      expect(result.success).toBe(true);
    });
  });
});
