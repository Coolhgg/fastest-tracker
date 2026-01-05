import { getClientIp, sanitizeInput, checkRateLimit } from '../../lib/api-utils';
import { isInternalIP, isWhitelistedDomain } from '../../lib/constants/image-whitelist';

describe('Bug Bounty Audit Integration Tests', () => {
  describe('Security: IP Extraction & Spoofing Prevention', () => {
    it('should correctly extract IP from X-Forwarded-For', () => {
      const request = new Request('https://test.com', {
        headers: { 'x-forwarded-for': '1.2.3.4, 192.168.1.1' }
      });
      expect(getClientIp(request)).toBe('1.2.3.4');
    });

    it('should fallback to X-Real-IP if X-Forwarded-For is missing', () => {
      const request = new Request('https://test.com', {
        headers: { 'x-real-ip': '5.6.7.8' }
      });
      expect(getClientIp(request)).toBe('5.6.7.8');
    });

    it('should return 127.0.0.1 as default fallback', () => {
      const request = new Request('https://test.com');
      expect(getClientIp(request)).toBe('127.0.0.1');
    });
  });

  describe('Security: Input Sanitization (XSS Prevention)', () => {
    it('should strip script tags', () => {
      const input = '<script>alert("xss")</script>Hello';
      expect(sanitizeInput(input)).toBe('Hello');
    });

    it('should strip dangerous event handlers', () => {
      const input = '<img src="x" onerror="alert(1)">';
      expect(sanitizeInput(input)).toBe('');
    });

    it('should strip dangerous protocols', () => {
      const input = 'javascript:alert(1)';
      expect(sanitizeInput(input)).toBe('alert(1)');
    });

    it('should truncate extremely long inputs', () => {
      const longInput = 'a'.repeat(25000);
      const sanitized = sanitizeInput(longInput, 10000);
      expect(sanitized.length).toBeLessThanOrEqual(10000);
    });
  });

  describe('Security: SSRF Prevention', () => {
    it('should detect internal IPv4 addresses', () => {
      expect(isInternalIP('127.0.0.1')).toBe(true);
      expect(isInternalIP('10.0.0.1')).toBe(true);
      expect(isInternalIP('192.168.1.1')).toBe(true);
      expect(isInternalIP('169.254.169.254')).toBe(true);
    });

    it('should detect internal IPv6 addresses', () => {
      expect(isInternalIP('::1')).toBe(true);
      expect(isInternalIP('fe80::1')).toBe(true);
    });

    it('should whitelist allowed domains correctly', () => {
      expect(isWhitelistedDomain('https://cdn.mangadex.org/covers/1.jpg')).toBe(true);
      expect(isWhitelistedDomain('https://evil.com/image.jpg')).toBe(false);
    });
  });

  describe('Robustness: Rate Limiting (Async)', () => {
    it('should be an async function', async () => {
      const result = checkRateLimit('test-key', 10, 60000);
      expect(result instanceof Promise).toBe(true);
      await expect(result).resolves.toBeDefined();
    });
  });
});
