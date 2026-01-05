import { prisma } from '@/lib/prisma';
import { processChapterIngest } from '@/workers/processors/chapter-ingest.processor';
import { Prisma } from '@prisma/client';

// Mock BullMQ Job
const mockJob = (data: any) => ({
  data,
  id: 'test-job',
} as any);

describe('V2 Audit Fixes & Integrity Tests', () => {
  const seriesId = '00000000-0000-0000-0000-000000000001';
  const sourceId = '00000000-0000-0000-0000-000000000002';

  beforeAll(async () => {
    // Setup test data
    await prisma.series.upsert({
      where: { id: seriesId },
      update: {},
      create: {
        id: seriesId,
        title: 'Test Series',
        type: 'manga',
        status: 'ongoing',
      },
    });

    await prisma.seriesSource.upsert({
      where: { id: sourceId },
      update: {},
      create: {
        id: sourceId,
        series_id: seriesId,
        source_name: 'mangadex',
        source_id: 'md-1',
        source_url: 'https://mangadex.org/title/test',
      },
    });
  });

  afterAll(async () => {
    // Cleanup
    await prisma.chapterSource.deleteMany({ where: { series_source_id: sourceId } });
    await prisma.logicalChapter.deleteMany({ where: { series_id: seriesId } });
  });

  describe('Ingest Processor: Metadata Protection', () => {
    it('should NOT overwrite existing title with null', async () => {
      const chapterNumber = 1;
      
      // 1. Ingest with title
      await processChapterIngest(mockJob({
        seriesId,
        seriesSourceId: sourceId,
        chapterNumber,
        chapterTitle: 'Good Title',
        chapterUrl: 'https://test.com/1',
        publishedAt: new Date().toISOString(),
      }));

      // 2. Ingest same chapter with null title
      await processChapterIngest(mockJob({
        seriesId,
        seriesSourceId: sourceId,
        chapterNumber,
        chapterTitle: null,
        chapterUrl: 'https://test.com/1-alt',
        publishedAt: new Date().toISOString(),
      }));

      const lc = await prisma.logicalChapter.findUnique({
        where: { series_id_chapter_number: { series_id: seriesId, chapter_number: new Prisma.Decimal(chapterNumber) } },
      });

      expect(lc?.chapter_title).toBe('Good Title');
    });

    it('should update title if it was previously null', async () => {
      const chapterNumber = 2;
      
      // 1. Ingest with null title
      await processChapterIngest(mockJob({
        seriesId,
        seriesSourceId: sourceId,
        chapterNumber,
        chapterTitle: null,
        chapterUrl: 'https://test.com/2',
        publishedAt: new Date().toISOString(),
      }));

      // 2. Ingest same chapter with good title
      await processChapterIngest(mockJob({
        seriesId,
        seriesSourceId: sourceId,
        chapterNumber,
        chapterTitle: 'Updated Title',
        chapterUrl: 'https://test.com/2-alt',
        publishedAt: new Date().toISOString(),
      }));

      const lc = await prisma.logicalChapter.findUnique({
        where: { series_id_chapter_number: { series_id: seriesId, chapter_number: new Prisma.Decimal(chapterNumber) } },
      });

      expect(lc?.chapter_title).toBe('Updated Title');
    });
  });

  describe('Database Trigger: latest_chapter Integrity', () => {
    it('should keep highest chapter number as latest_chapter even if ingested out of order', async () => {
      // 1. Ingest Chapter 10
      await processChapterIngest(mockJob({
        seriesId,
        seriesSourceId: sourceId,
        chapterNumber: 10,
        chapterTitle: 'Ch 10',
        chapterUrl: 'https://test.com/10',
        publishedAt: new Date().toISOString(),
      }));

      let series = await prisma.series.findUnique({ where: { id: seriesId } });
      expect(Number(series?.latest_chapter)).toBe(10);

      // 2. Ingest Chapter 5 (out of order)
      await processChapterIngest(mockJob({
        seriesId,
        seriesSourceId: sourceId,
        chapterNumber: 5,
        chapterTitle: 'Ch 5',
        chapterUrl: 'https://test.com/5',
        publishedAt: new Date().toISOString(),
      }));

      series = await prisma.series.findUnique({ where: { id: seriesId } });
      // Should STILL be 10, not 5
      expect(Number(series?.latest_chapter)).toBe(10);

      // 3. Ingest Chapter 11
      await processChapterIngest(mockJob({
        seriesId,
        seriesSourceId: sourceId,
        chapterNumber: 11,
        chapterTitle: 'Ch 11',
        chapterUrl: 'https://test.com/11',
        publishedAt: new Date().toISOString(),
      }));

      series = await prisma.series.findUnique({ where: { id: seriesId } });
      expect(Number(series?.latest_chapter)).toBe(11);
    });
  });
});
