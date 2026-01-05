export interface ScrapedChapter {
  chapterNumber: number;
  chapterTitle?: string;
  chapterUrl: string;
  publishedAt?: Date;
}

export interface ScrapedSeries {
  sourceId: string;
  title: string;
  chapters: ScrapedChapter[];
}

export interface Scraper {
  scrapeSeries(sourceId: string): Promise<ScrapedSeries>;
}

// Allowed hostnames to prevent SSRF
const ALLOWED_HOSTS = new Set([
  'mangapark.io',
  'www.mangapark.io',
  'mangadex.org',
  'api.mangadex.org',
  'comick.io',
  'api.comick.io',
  'mangasee123.com',
]);

// SECURITY: Validate source ID format to prevent injection
const SOURCE_ID_REGEX = /^[a-zA-Z0-9_-]{1,100}$/;

export function validateSourceId(sourceId: string): boolean {
  return SOURCE_ID_REGEX.test(sourceId);
}

export function validateSourceUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ALLOWED_HOSTS.has(parsed.hostname);
  } catch {
    return false;
  }
}

export class ScraperError extends Error {
  constructor(
    message: string,
    public readonly source: string,
    public readonly isRetryable: boolean = true,
    public readonly code?: string
  ) {
    super(message);
    this.name = 'ScraperError';
  }
}

export class SelectorNotFoundError extends ScraperError {
  constructor(source: string, selector: string) {
    super(`Selector not found: ${selector}`, source, false, 'SELECTOR_NOT_FOUND');
    this.name = 'SelectorNotFoundError';
  }
}

export class ProxyBlockedError extends ScraperError {
  constructor(source: string) {
    super('Request blocked by proxy/WAF', source, true, 'PROXY_BLOCKED');
    this.name = 'ProxyBlockedError';
  }
}

export class RateLimitError extends ScraperError {
  constructor(source: string) {
    super('Rate limit exceeded', source, true, 'RATE_LIMIT');
    this.name = 'RateLimitError';
  }
}

export class CircuitBreakerOpenError extends ScraperError {
  constructor(source: string) {
    super(`Circuit breaker is open for source: ${source}`, source, false, 'CIRCUIT_OPEN');
    this.name = 'CircuitBreakerOpenError';
  }
}

class CircuitBreaker {
  private failures = 0;
  private lastFailureAt: number | null = null;
  private readonly threshold = 5;
  private readonly resetTimeout = 60000; // 1 minute

  isOpen(): boolean {
    if (this.failures >= this.threshold) {
      if (this.lastFailureAt && Date.now() - this.lastFailureAt > this.resetTimeout) {
        this.failures = 0;
        return false;
      }
      return true;
    }
    return false;
  }

  recordFailure(): void {
    this.failures++;
    this.lastFailureAt = Date.now();
  }

  recordSuccess(): void {
    this.failures = 0;
    this.lastFailureAt = null;
  }
}

const breakers: Record<string, CircuitBreaker> = {};

function getBreaker(source: string): CircuitBreaker {
  if (!breakers[source]) {
    breakers[source] = new CircuitBreaker();
  }
  return breakers[source];
}

export class MangaParkScraper implements Scraper {
  private readonly TIMEOUT_MS = 30000;

  async scrapeSeries(sourceId: string): Promise<ScrapedSeries> {
    const breaker = getBreaker('mangapark');
    if (breaker.isOpen()) {
      throw new CircuitBreakerOpenError('mangapark');
    }

    console.log(`[MangaPark] Scraping sourceId: ${sourceId}`);
    
    try {
      // Simulate network delay with timeout
      await Promise.race([
        new Promise(resolve => setTimeout(resolve, 1000)),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Timeout')), this.TIMEOUT_MS)
        ),
      ]);

      // Mock success
      breaker.recordSuccess();

      // Mock response
      return {
        sourceId,
        title: `MangaPark - ${sourceId}`,
        chapters: [
          {
            chapterNumber: 1,
            chapterTitle: "The Beginning",
            chapterUrl: `https://mangapark.io/title/${encodeURIComponent(sourceId)}/c1`,
            publishedAt: new Date(Date.now() - 86400000 * 10),
          },
          {
            chapterNumber: 2,
            chapterTitle: "The Journey",
            chapterUrl: `https://mangapark.io/title/${encodeURIComponent(sourceId)}/c2`,
            publishedAt: new Date(Date.now() - 86400000 * 5),
          },
          {
            chapterNumber: 3,
            chapterTitle: "New Discovery",
            chapterUrl: `https://mangapark.io/title/${encodeURIComponent(sourceId)}/c3`,
            publishedAt: new Date(),
          }
        ]
      };
    } catch (error) {
      breaker.recordFailure();
      throw new ScraperError(
        `MangaPark scraping failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'mangapark',
        true
      );
    }
  }
}

export class MangaDexScraper implements Scraper {
  private readonly BASE_URL = 'https://api.mangadex.org';
  private readonly TIMEOUT_MS = 30000;
  private readonly UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

  async scrapeSeries(sourceId: string): Promise<ScrapedSeries> {
    const breaker = getBreaker('mangadex');
    if (breaker.isOpen()) {
      throw new CircuitBreakerOpenError('mangadex');
    }

    // SECURITY: Validate UUID format before making external request
    if (!this.UUID_REGEX.test(sourceId)) {
      throw new ScraperError('Invalid MangaDex ID format', 'mangadex', false);
    }
    
    console.log(`[MangaDex] Fetching sourceId: ${sourceId}`);
    
    try {
      // 1. Fetch Manga Details
      const mangaResponse = await fetch(`${this.BASE_URL}/manga/${sourceId}`, {
        signal: AbortSignal.timeout(this.TIMEOUT_MS)
      });

      if (mangaResponse.status === 429) {
        throw new RateLimitError('mangadex');
      }

      if (!mangaResponse.ok) {
        if (mangaResponse.status === 403 || mangaResponse.status === 401) {
          throw new ProxyBlockedError('mangadex');
        }
        throw new Error(`Failed to fetch manga details: ${mangaResponse.statusText}`);
      }

      const mangaData = await mangaResponse.json();
      const title = mangaData.data.attributes.title.en || 
                    Object.values(mangaData.data.attributes.title)[0] as string;

      // 2. Fetch Chapters
      const chaptersResponse = await fetch(
        `${this.BASE_URL}/manga/${sourceId}/feed?limit=500&translatedLanguage[]=en&order[chapter]=asc&contentRating[]=safe&contentRating[]=suggestive&contentRating[]=erotica&contentRating[]=pornographic`,
        { signal: AbortSignal.timeout(this.TIMEOUT_MS) }
      );

      if (!chaptersResponse.ok) {
        throw new Error(`Failed to fetch chapters: ${chaptersResponse.statusText}`);
      }

      const chaptersData = await chaptersResponse.json();
      
      const chapters: ScrapedChapter[] = chaptersData.data.map((item: any) => ({
        chapterNumber: parseFloat(item.attributes.chapter) || 0,
        chapterTitle: item.attributes.title || `Chapter ${item.attributes.chapter}`,
        chapterUrl: `https://mangadex.org/chapter/${item.id}`,
        publishedAt: new Date(item.attributes.publishAt),
      }));

      breaker.recordSuccess();

      return {
        sourceId,
        title,
        chapters
      };
    } catch (error) {
      if (!(error instanceof RateLimitError)) {
        breaker.recordFailure();
      }
      
      if (error instanceof ScraperError) throw error;

      console.error(`[MangaDex] Scraping failed for ${sourceId}:`, error);
      throw new ScraperError(
        `MangaDex fetch failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'mangadex',
        true
      );
    }
  }
}

export const scrapers: Record<string, Scraper> = {
  'mangapark': new MangaParkScraper(),
  'mangadex': new MangaDexScraper(),
};
