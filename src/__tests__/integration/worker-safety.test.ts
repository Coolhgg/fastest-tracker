import { prisma } from '@/lib/prisma';
import { redis } from '@/lib/redis';
import { processChapterIngest } from '@/workers/processors/chapter-ingest.processor';
import { processNotificationDelivery } from '@/workers/processors/notification-delivery.processor';
import { Job } from 'bullmq';
import { v4 as uuidv4 } from 'uuid';

describe('Worker Safety & Idempotency Integration Tests', () => {
  let testUser: any;
  let testSeries: any;
  let testSource: any;

  beforeAll(async () => {
    // Setup test data
    testUser = await prisma.user.create({
      data: {
        id: uuidv4(),
        email: `test-${Date.now()}@example.com`,
        username: `testuser-${Date.now()}`,
      }
    });

    testSeries = await prisma.series.create({
      data: {
        id: uuidv4(),
        title: 'Test Series',
        slug: `test-series-${Date.now()}`,
      }
    });

    testSource = await prisma.seriesSource.create({
      data: {
        id: uuidv4(),
        series_id: testSeries.id,
        source_id: 'test-source',
        source_url: 'https://example.com/test',
      }
    });
  });

  afterAll(async () => {
    // Cleanup
    await prisma.notification.deleteMany({ where: { user_id: testUser.id } });
    await prisma.chapterSource.deleteMany({ where: { series_source_id: testSource.id } });
    await prisma.logicalChapter.deleteMany({ where: { series_id: testSeries.id } });
    await prisma.seriesSource.delete({ where: { id: testSource.id } });
    await prisma.series.delete({ where: { id: testSeries.id } });
    await prisma.user.delete({ where: { id: testUser.id } });
  });

  test('Chapter Ingestion should be idempotent and not double-count sources', async () => {
    const jobData = {
      seriesSourceId: testSource.id,
      seriesId: testSeries.id,
      chapterNumber: 1,
      chapterTitle: 'Chapter 1',
      chapterUrl: 'https://example.com/test/1',
      publishedAt: new Date().toISOString(),
    };

    const mockJob = { id: 'test-job-1', data: jobData } as Job;

    // Run ingestion first time
    await processChapterIngest(mockJob);

    const sourceAfterFirst = await prisma.seriesSource.findUnique({
      where: { id: testSource.id }
    });
    expect(sourceAfterFirst?.source_chapter_count).toBe(1);

    // Run ingestion second time (simulating retry or duplicate job)
    await processChapterIngest(mockJob);

    const sourceAfterSecond = await prisma.seriesSource.findUnique({
      where: { id: testSource.id }
    });
    // Should still be 1, not 2
    expect(sourceAfterSecond?.source_chapter_count).toBe(1);
  });

  test('Notification Delivery should be idempotent per user/chapter', async () => {
    const jobData = {
      seriesId: testSeries.id,
      sourceId: testSource.id,
      chapterNumber: 1,
      newChapterCount: 1,
      userIds: [testUser.id],
      isPremium: false,
    };

    const mockJob = { id: 'test-notify-1', data: jobData } as Job;

    // Run delivery first time
    await processNotificationDelivery(mockJob);

    const notificationsCount = await prisma.notification.count({
      where: { user_id: testUser.id, series_id: testSeries.id }
    });
    expect(notificationsCount).toBe(1);

    // Run delivery second time (simulating retry or duplicate job)
    await processNotificationDelivery(mockJob);

    const notificationsCountAfterSecond = await prisma.notification.count({
      where: { user_id: testUser.id, series_id: testSeries.id }
    });
    // Should still be 1, not 2
    expect(notificationsCountAfterSecond).toBe(1);
  });
});
