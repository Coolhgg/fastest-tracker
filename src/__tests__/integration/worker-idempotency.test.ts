import { prisma } from '@/lib/prisma';
import { redis } from '@/lib/redis';
import { processChapterIngest } from '@/workers/processors/chapter-ingest.processor';
import { processNotificationDelivery } from '@/workers/processors/notification-delivery.processor';
import { Job } from 'bullmq';

describe('Worker Idempotency Integration Tests', () => {
  let testSeries: any;
  let testSource: any;
  let testUser: any;

  beforeAll(async () => {
    // Setup test data
    testUser = await prisma.user.create({
      data: {
        email: `test-worker-${Date.now()}@example.com`,
        username: `testworker_${Date.now()}`,
      }
    });

    testSeries = await prisma.series.create({
      data: {
        title: 'Test Worker Series',
        type: 'manga',
      }
    });

    testSource = await prisma.seriesSource.create({
      data: {
        series_id: testSeries.id,
        source_name: 'test_source',
        source_id: 'test-id',
        source_url: 'https://example.com/test',
      }
    });

    await prisma.libraryEntry.create({
      data: {
        user_id: testUser.id,
        series_id: testSeries.id,
        status: 'reading',
        notify_new_chapters: true,
      }
    });
  });

  afterAll(async () => {
    // Cleanup
    await prisma.notification.deleteMany({ where: { user_id: testUser.id } });
    await prisma.libraryEntry.deleteMany({ where: { user_id: testUser.id } });
    await prisma.userChapterReadV2.deleteMany({ where: { user_id: testUser.id } });
    await prisma.seriesSource.delete({ where: { id: testSource.id } });
    await prisma.series.delete({ where: { id: testSeries.id } });
    await prisma.user.delete({ where: { id: testUser.id } });
  });

  it('should not create duplicate chapters on retry (Chapter Ingest Idempotency)', async () => {
    const jobData = {
      seriesSourceId: testSource.id,
      seriesId: testSeries.id,
      chapterNumber: 1,
      chapterTitle: 'Chapter 1',
      chapterUrl: 'https://example.com/chapter1',
      publishedAt: new Date().toISOString(),
    };

    const mockJob = { data: jobData } as Job;

    // Run twice
    await processChapterIngest(mockJob);
    await processChapterIngest(mockJob);

    // Verify only one logical chapter and one chapter source
    const logicalChapters = await prisma.logicalChapter.findMany({
      where: { series_id: testSeries.id, chapter_number: 1 }
    });
    expect(logicalChapters).toHaveLength(1);

    const chapterSources = await prisma.chapterSource.findMany({
      where: { series_source_id: testSource.id, chapter_id: logicalChapters[0].id }
    });
    expect(chapterSources).toHaveLength(1);
  });

  it('should not create duplicate notifications on retry (Notification Delivery Idempotency)', async () => {
    const jobData = {
      seriesId: testSeries.id,
      sourceId: testSource.id,
      chapterNumber: 1,
      newChapterCount: 1,
      userIds: [testUser.id],
      isPremium: false,
    };

    const mockJob = { id: 'test-job-id', data: jobData } as Job;

    // Run twice
    await processNotificationDelivery(mockJob);
    await processNotificationDelivery(mockJob);

    // Verify only one notification
    const notifications = await prisma.notification.findMany({
      where: { user_id: testUser.id, series_id: testSeries.id, type: 'NEW_CHAPTER' }
    });
    
    // Filters notifications for chapter 1 based on metadata
    const chapter1Notifications = notifications.filter(n => 
      (n.metadata as any)?.chapter_number === 1
    );

    expect(chapter1Notifications).toHaveLength(1);
  });
});
