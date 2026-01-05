import { escapeILikePattern, USERNAME_REGEX, validateUsername } from '../lib/api-utils';

describe('Bounty Fixes Verification', () => {
  describe('Bug #1: ILIKE Escaping', () => {
    it('should escape special characters in ILIKE patterns', () => {
      expect(escapeILikePattern('test%query_with\\backslashes')).toBe('test\\%query\\_with\\\\backslashes');
      expect(escapeILikePattern('%')).toBe('\\%');
      expect(escapeILikePattern('_')).toBe('\\_');
      expect(escapeILikePattern('\\')).toBe('\\\\');
    });
  });

  describe('Bug #9: Username Validation Regex', () => {
    it('should validate usernames according to standardized regex', () => {
      expect(validateUsername('valid_user-name')).toBe(true);
      expect(validateUsername('user123')).toBe(true);
      expect(validateUsername('abc')).toBe(true); // min 3
      expect(validateUsername('ab')).toBe(false); // too short
      expect(validateUsername('this_is_a_very_long_username_that_should_fail')).toBe(false); // max 30
      expect(validateUsername('user!name')).toBe(false); // special char
      expect(validateUsername('user name')).toBe(false); // space
    });

    it('should match the constant regex', () => {
      expect(USERNAME_REGEX.test('manga-reader_01')).toBe(true);
      expect(USERNAME_REGEX.test('manga.reader')).toBe(false);
    });
  });
});
