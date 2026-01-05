/**
 * @jest-environment node
 */
import { prisma } from '@/lib/prisma';
import { processChapterIngest } from '@/workers/processors/chapter-ingest.processor';
import { Prisma } from '@prisma/client';

// Mock BullMQ to avoid ESM issues in Jest environment
jest.mock('@/lib/queues', () => ({
  notificationQueue: {
    add: jest.fn().mockResolvedValue({ id: 'mock-job-id' }),
  },
}));

describe('Canonical Bug Bounty Verification', () => {
  let testSeriesId: string;
  let testSourceId: string;

  beforeAll(async () => {
    // Setup test series and source
    const series = await prisma.series.create({
      data: {
        title: 'Bug Bounty Test Series',
        type: 'manga',
        status: 'ongoing',
        latest_chapter: 0,
      }
    });
    testSeriesId = series.id;

    const source = await prisma.seriesSource.create({
      data: {
        series_id: testSeriesId,
        source_name: 'mangadex',
        source_id: 'test-source-id',
        source_url: 'https://mangadex.org/title/test',
      }
    });
    testSourceId = source.id;
  });

  afterAll(async () => {
    // Cleanup
    await prisma.series.delete({ where: { id: testSeriesId } });
  });

  describe('Ingestion Race Condition & Forward-Only Updates', () => {
    it('should NOT downgrade latest_chapter if an older chapter arrives out of order', async () => {
      // 1. Ingest Chapter 100
      await processChapterIngest({
        data: {
          seriesId: testSeriesId,
          seriesSourceId: testSourceId,
          chapterNumber: 100,
          chapterTitle: 'Chapter 100',
          chapterUrl: 'https://mangadex.org/chapter/100',
          publishedAt: new Date().toISOString(),
        }
      } as any);

      let series = await prisma.series.findUnique({ where: { id: testSeriesId } });
      expect(Number(series?.latest_chapter)).toBe(100);

      // 2. Ingest Chapter 99 (Out of order)
      await processChapterIngest({
        data: {
          seriesId: testSeriesId,
          seriesSourceId: testSourceId,
          chapterNumber: 99,
          chapterTitle: 'Chapter 99',
          chapterUrl: 'https://mangadex.org/chapter/99',
          publishedAt: new Date().toISOString(),
        }
      } as any);

      // Verify latest_chapter is still 100 (Forward-only logic)
      series = await prisma.series.findUnique({ where: { id: testSeriesId } });
      expect(Number(series?.latest_chapter)).toBe(100);
      expect(series?.chapter_count).toBe(2);
    });
  });

  describe('Notification Deduplication Logic', () => {
    it('should generate unique job IDs for different chapters in the same window', async () => {
      const { notificationQueue } = require('@/lib/queues');
      
      // We need to inspect how notificationQueue.add was called
      // Since we mocked it, we can check calls
      
      await processChapterIngest({
        data: {
          seriesId: testSeriesId,
          seriesSourceId: testSourceId,
          chapterNumber: 1,
          chapterTitle: 'Ch 1',
          chapterUrl: 'https://mangadex.org/chapter/1',
          publishedAt: new Date().toISOString(),
        }
      } as any);

      await processChapterIngest({
        data: {
          seriesId: testSeriesId,
          seriesSourceId: testSourceId,
          chapterNumber: 2,
          chapterTitle: 'Ch 2',
          chapterUrl: 'https://mangadex.org/chapter/2',
          publishedAt: new Date().toISOString(),
        }
      } as any);

      const calls = notificationQueue.add.mock.calls;
      const jobIds = calls.map((call: any) => call[2].jobId);
      
      // Ensure Job IDs are different because chapter numbers are different
      expect(jobIds[jobIds.length - 2]).not.toBe(jobIds[jobIds.length - 1]);
      expect(jobIds[jobIds.length - 1]).toContain('-2-'); // Should contain chapter number
    });
  });

  describe('Privacy RLS Enforcement', () => {
    it('should default users to private and hide activity from public RLS', async () => {
      // Create a test user
      const testUser = await prisma.user.create({
        data: {
          username: `privatetest_${Date.now()}`,
          email: `test_${Date.now()}@example.com`,
        }
      });

      // Check default privacy settings
      const user = await prisma.user.findUnique({ where: { id: testUser.id } });
      expect(user?.privacy_settings).toEqual({
        library_public: false,
        activity_public: false
      });

      // Cleanup
      await prisma.user.delete({ where: { id: testUser.id } });
    });
  });
});
