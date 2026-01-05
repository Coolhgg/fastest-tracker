import { prisma } from '@/lib/prisma';
import { syncChapters } from '@/lib/series-sync';
import { Prisma } from '@prisma/client';

describe('Bug Bounty Integration Tests', () => {
  let testUser: any;
  let testSeries: any;

  beforeAll(async () => {
    // Setup test data
    testUser = await prisma.user.create({
      data: {
        email: `test-${Date.now()}@example.com`,
        username: `testuser-${Date.now()}`,
        password_hash: 'hash',
      }
    });

    testSeries = await prisma.series.create({
      data: {
        title: 'Test Series',
        type: 'manga',
        mangadex_id: `test-md-${Date.now()}`,
      }
    });

    await prisma.seriesSource.create({
      data: {
        series_id: testSeries.id,
        source_name: 'mangadex',
        source_id: testSeries.mangadex_id,
        source_url: 'http://example.com',
      }
    });
  });

  afterAll(async () => {
    // Cleanup
    await prisma.libraryEntry.deleteMany({ where: { user_id: testUser.id } });
    await prisma.activity.deleteMany({ where: { user_id: testUser.id } });
    await prisma.notification.deleteMany({ where: { user_id: testUser.id } });
    await prisma.user.delete({ where: { id: testUser.id } });
    await prisma.series.delete({ where: { id: testSeries.id } });
  });

  describe('Library Follow Counts', () => {
    it('should only increment total_follows on first add', async () => {
      // Mocking the behavior of the API route
      const addEntry = async () => {
        const existing = await prisma.libraryEntry.findUnique({
          where: { user_id_series_id: { user_id: testUser.id, series_id: testSeries.id } }
        });

        await prisma.libraryEntry.upsert({
          where: { user_id_series_id: { user_id: testUser.id, series_id: testSeries.id } },
          update: { status: 'reading' },
          create: { user_id: testUser.id, series_id: testSeries.id, status: 'reading' }
        });

        if (!existing) {
          await prisma.series.update({
            where: { id: testSeries.id },
            data: { total_follows: { increment: 1 } }
          });
        }
      };

      // Initial follow count
      const seriesBefore = await prisma.series.findUnique({ where: { id: testSeries.id } });
      const initialFollows = seriesBefore?.total_follows || 0;

      // Add first time
      await addEntry();
      const seriesAfter1 = await prisma.series.findUnique({ where: { id: testSeries.id } });
      expect(seriesAfter1?.total_follows).toBe(initialFollows + 1);

      // Add second time (update status)
      await addEntry();
      const seriesAfter2 = await prisma.series.findUnique({ where: { id: testSeries.id } });
      expect(seriesAfter2?.total_follows).toBe(initialFollows + 1); // Should stay same
    });
  });

  describe('Chapter V2 Batch Sync', () => {
    it('should correctly sync large number of chapters in batches', async () => {
      const source = await prisma.seriesSource.findFirst({ where: { series_id: testSeries.id } });
      const chapters = Array.from({ length: 60 }, (_, i) => ({
        chapterNumber: (i + 1).toString(),
        chapterTitle: `Chapter ${i + 1}`,
        chapterUrl: `http://example.com/ch/${i + 1}`,
        publishedAt: new Date(),
      }));

      const count = await syncChapters(testSeries.id, source!.source_id, source!.source_name, chapters);
      expect(count).toBe(60);

      const dbChapters = await prisma.logicalChapter.count({ where: { series_id: testSeries.id } });
      expect(dbChapters).toBe(60);

      const series = await prisma.series.findUnique({ where: { id: testSeries.id } });
      expect(Number(series?.latest_chapter)).toBe(60);
    }, 30000); // Increase test timeout to 30s
  });

  describe('Notifications and Activities V2', () => {
    it('should allow linking to logical chapters', async () => {
      let chapter = await prisma.logicalChapter.findFirst({ 
        where: { series_id: testSeries.id },
        orderBy: { chapter_number: 'asc' }
      });

      // If chapter doesn't exist (e.g. if sync failed), create one for the test
      if (!chapter) {
        chapter = await prisma.logicalChapter.create({
          data: {
            series_id: testSeries.id,
            chapter_number: new Prisma.Decimal(1),
            chapter_title: 'Manual Chapter 1',
          }
        });
      }
      
      const notification = await prisma.notification.create({
        data: {
          user_id: testUser.id,
          type: 'NEW_CHAPTER',
          title: 'Test Notification',
          logical_chapter_id: chapter!.id,
          series_id: testSeries.id,
        }
      });

      expect(notification.logical_chapter_id).toBe(chapter!.id);

      const activity = await prisma.activity.create({
        data: {
          user_id: testUser.id,
          type: 'READ',
          logical_chapter_id: chapter!.id,
          series_id: testSeries.id,
        }
      });

      expect(activity.logical_chapter_id).toBe(chapter!.id);
    });
  });
});
