/**
 * MangaDex Configuration Utility
 * Securely manages server-side credentials and headers.
 */

const MANGADEX_CLIENT_ID = process.env.MANGADEX_CLIENT_ID;
const MANGADEX_CLIENT_SECRET = process.env.MANGADEX_CLIENT_SECRET;
export const MANGADEX_API_BASE = process.env.MANGADEX_API_BASE || 'https://api.mangadex.org';

/**
 * Generates headers for MangaDex API requests.
 * Attaches Authorization if client credentials are provided.
 */
export function getMangaDexHeaders() {
  const headers: Record<string, string> = {
    'User-Agent': 'Orchids/1.0 (https://github.com/orchids-app)',
    'Accept': 'application/json',
  };

  // Only attach Authorization if both credentials exist
  if (MANGADEX_CLIENT_ID && MANGADEX_CLIENT_SECRET) {
    // Basic Auth for client credentials (as per MangaDex Personal Client docs)
    const auth = Buffer.from(`${MANGADEX_CLIENT_ID}:${MANGADEX_CLIENT_SECRET}`).toString('base64');
    headers['Authorization'] = `Basic ${auth}`;
  }

  return headers;
}
