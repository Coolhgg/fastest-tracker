import { prisma } from '@/lib/prisma';
import { processChapterIngest } from '@/workers/processors/chapter-ingest.processor';
import { Prisma } from '@prisma/client';

describe('Bounty Implementation Integration Tests', () => {
  let testSeries: any;
  let testSource: any;

  beforeAll(async () => {
    // Setup test data
    testSeries = await prisma.series.create({
      data: {
        title: 'Bounty Test Series',
        type: 'MANGA',
        status: 'ONGOING',
      },
    });

    testSource = await prisma.seriesSource.create({
      data: {
        series_id: testSeries.id,
        source_name: 'test-source',
        source_id: 'test-source-id',
        source_url: 'https://test.com',
      },
    });
  });

  afterAll(async () => {
    // Cleanup
    if (testSeries) {
      await prisma.series.delete({ where: { id: testSeries.id } });
    }
  });

  describe('Chapter Ingestion Race Conditions & Triggers', () => {
    it('should correctly update latest_chapter and chapter_count via DB triggers', async () => {
      // 1. Ingest Chapter 10
      await processChapterIngest({
        data: {
          seriesId: testSeries.id,
          seriesSourceId: testSource.id,
          chapterNumber: 10,
          chapterTitle: 'Chapter 10',
          chapterUrl: 'https://test.com/10',
          publishedAt: new Date().toISOString(),
        }
      } as any);

      let series = await prisma.series.findUnique({ where: { id: testSeries.id } });
      expect(Number(series?.latest_chapter)).toBe(10);
      expect(series?.chapter_count).toBe(1);

      // 2. Ingest Chapter 5 (out of order)
      await processChapterIngest({
        data: {
          seriesId: testSeries.id,
          seriesSourceId: testSource.id,
          chapterNumber: 5,
          chapterTitle: 'Chapter 5',
          chapterUrl: 'https://test.com/5',
          publishedAt: new Date().toISOString(),
        }
      } as any);

      series = await prisma.series.findUnique({ where: { id: testSeries.id } });
      expect(Number(series?.latest_chapter)).toBe(10); // Should still be 10
      expect(series?.chapter_count).toBe(2); // Should be 2 unique logical chapters

      // 3. Ingest same chapter from another source (should not increment chapter_count)
      const testSource2 = await prisma.seriesSource.create({
        data: {
          series_id: testSeries.id,
          source_name: 'test-source-2',
          source_id: 'test-source-2-id',
          source_url: 'https://test2.com',
        },
      });

      await processChapterIngest({
        data: {
          seriesId: testSeries.id,
          seriesSourceId: testSource2.id,
          chapterNumber: 10,
          chapterTitle: 'Chapter 10 (Alt)',
          chapterUrl: 'https://test2.com/10',
          publishedAt: new Date().toISOString(),
        }
      } as any);

      series = await prisma.series.findUnique({ where: { id: testSeries.id } });
      expect(series?.chapter_count).toBe(2); // Still 2 unique logical chapters
      
      // Cleanup source 2
      await prisma.seriesSource.delete({ where: { id: testSource2.id } });
    });
  });
});
