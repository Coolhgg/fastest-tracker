import { processCheckSource } from '@/workers/processors/check-source.processor';
import { prisma } from '@/lib/prisma';
import { canonicalizeQueue } from '@/lib/queues';
import { MangaDexScraper } from '@/lib/scrapers';

// Mock dependencies
jest.mock('@/lib/prisma', () => ({
  prisma: {
    series: {
      findUnique: jest.fn(),
    },
  },
}));

jest.mock('@/lib/queues', () => ({
  canonicalizeQueue: {
    add: jest.fn(),
  },
}));

jest.mock('@/lib/scrapers', () => ({
  MangaDexScraper: jest.fn().mockImplementation(() => ({
    scrapeSeries: jest.fn().mockResolvedValue({
      sourceId: 'md-1',
      title: 'Test Manga',
      chapters: [
        { chapterNumber: 1, chapterTitle: 'Ch 1', chapterUrl: 'url1', publishedAt: new Date() }
      ]
    })
  })),
  scrapers: {
    'mangadex': {
      scrapeSeries: jest.fn().mockResolvedValue({
        sourceId: 'md-1',
        title: 'Test Manga',
        chapters: []
      })
    }
  }
}));

jest.mock('@/lib/mangadex', () => ({
  getMangaDexHeaders: jest.fn().mockReturnValue({}),
  MANGADEX_API_BASE: 'https://api.mangadex.org',
  getMangaDexCoverUrl: jest.fn().mockReturnValue('cover-url'),
}));

jest.mock('@/lib/rate-limiter', () => ({
  sourceRateLimiter: {
    acquireToken: jest.fn().mockResolvedValue(true),
  },
}));

describe('Worker Pipeline - Check Source', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Setup global fetch mock for MangaDex API calls in processor
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: jest.fn().mockResolvedValue({
        data: [],
        included: [],
        statistics: {}
      })
    }) as jest.Mock;
  });

  it('should process a search query and enqueue candidates', async () => {
    // Mock MangaDex search response
    (global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: jest.fn().mockResolvedValue({
        data: [
          {
            id: 'manga-1',
            type: 'manga',
            attributes: {
              title: { en: 'Solo Leveling' },
              description: { en: 'A great manga' },
              status: 'ongoing',
              contentRating: 'safe',
              tags: []
            },
            relationships: []
          }
        ],
        included: [],
        statistics: {}
      })
    });

    const mockJob = {
      id: 'job-1',
      data: {
        query: 'Solo Leveling',
        trigger: 'user_search'
      }
    } as any;

    const result = await processCheckSource(mockJob);

    expect(result.found).toBe(1);
    expect(canonicalizeQueue.add).toHaveBeenCalledWith(
      'canonicalize',
      expect.objectContaining({
        source_id: 'manga-1',
        title: 'Solo Leveling'
      }),
      expect.objectContaining({
        jobId: 'canon_mangadex_manga-1'
      })
    );
  });

  it('should handle missing search term by falling back to series title', async () => {
    (prisma.series.findUnique as jest.Mock).mockResolvedValue({ title: 'Fallback Title' });
    
    (global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: jest.fn().mockResolvedValue({ data: [], included: [] })
    });

    const mockJob = {
      id: 'job-2',
      data: {
        series_id: 'series-uuid',
        trigger: 'system_sync'
      }
    } as any;

    await processCheckSource(mockJob);

    expect(prisma.series.findUnique).toHaveBeenCalledWith({
      where: { id: 'series-uuid' },
      select: { title: true }
    });
  });
});
