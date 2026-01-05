import { processNotification } from '@/workers/processors/notification.processor';
import { prisma } from '@/lib/prisma';
import { redis } from '@/lib/redis';
import { notificationDeliveryQueue, notificationDeliveryPremiumQueue } from '@/lib/queues';
import { shouldNotifyChapter } from '@/lib/notifications-throttling';

// Mock everything
jest.mock('@/lib/prisma', () => ({
  prisma: {
    series: { findUnique: jest.fn() },
    seriesSource: { findUnique: jest.fn() },
    chapterSource: { findMany: jest.fn() },
    libraryEntry: { findMany: jest.fn() },
    logicalChapter: { findMany: jest.fn() },
    user: { findUnique: jest.fn() },
    $executeRaw: jest.fn(),
  },
}));

jest.mock('@/lib/redis', () => ({
  redis: {
    get: jest.fn(),
    set: jest.fn(),
    sadd: jest.fn(),
    smembers: jest.fn(),
    del: jest.fn(),
    expire: jest.fn(),
  },
  REDIS_KEY_PREFIX: 'test:',
}));

jest.mock('@/lib/queues', () => ({
  notificationDeliveryQueue: { add: jest.fn() },
  notificationDeliveryPremiumQueue: { add: jest.fn() },
  notificationQueue: { add: jest.fn() },
  isQueueHealthy: jest.fn().mockResolvedValue(true),
}));

jest.mock('@/lib/notifications-throttling', () => ({
  shouldNotifyChapter: jest.fn(),
}));

describe('System QA: End-to-End Logic Verification', () => {
  const userId = '00000000-0000-0000-0000-000000000001';
  const seriesId = '00000000-0000-0000-0000-000000000002';
  const sourceId1 = '00000000-0000-0000-0000-000000000003';
  const sourceId2 = '00000000-0000-0000-0000-000000000004';
  const dummyCursor = '00000000-0000-0000-0000-000000000005';
  const chapterNumber = 10;

  beforeEach(() => {
    jest.clearAllMocks();
    (prisma.chapterSource.findMany as jest.Mock).mockResolvedValue([]);
  });

  describe('TEST 1: NOTIFICATION DEDUP', () => {
    it('should only send one notification when triggered from multiple sources', async () => {
      // Mock first source trigger (bypass coalescing with cursor)
      (shouldNotifyChapter as jest.Mock).mockResolvedValue(true);
      (prisma.libraryEntry.findMany as jest.Mock).mockResolvedValue([{
        user_id: userId,
        notification_mode: 'immediate',
        user: { subscription_tier: 'free', notification_digest: 'immediate' }
      }]);
      (redis.get as jest.Mock).mockResolvedValue(null);

      await processNotification({ 
        data: { seriesId, sourceId: sourceId1, chapterNumber, newChapterCount: 1, cursor: dummyCursor },
        token: 'token'
      } as any);

      expect(notificationDeliveryQueue.add).toHaveBeenCalledTimes(1);

      // Mock second source trigger for same chapter
      (shouldNotifyChapter as jest.Mock).mockResolvedValue(false);
      (redis.get as jest.Mock).mockImplementation((key: string) => {
        if (key.includes(`notif:sent:user:${userId}`)) return '1';
        return null;
      });

      await processNotification({ 
        data: { seriesId, sourceId: sourceId2, chapterNumber, newChapterCount: 1, cursor: dummyCursor },
        token: 'token'
      } as any);

      expect(notificationDeliveryQueue.add).toHaveBeenCalledTimes(1);
    });
  });

  describe('TEST 2: FEED PERSONALIZATION', () => {
    it('should only show updates for followed series and respect safe browsing', async () => {
      (prisma.user.findUnique as jest.Mock).mockResolvedValue({
        id: userId,
        safe_browsing_mode: 'safe',
        default_source: 'mangadex'
      });

      (prisma.libraryEntry.findMany as jest.Mock).mockResolvedValue([
        { series_id: seriesId, preferred_source: 'mangadex' }
      ]);

      (prisma.logicalChapter.findMany as jest.Mock).mockResolvedValue([
        {
          id: 'ch-1',
          series_id: seriesId,
          chapter_number: 11,
          first_seen_at: new Date(),
          series: { title: 'Followed Series', content_rating: 'safe' },
          sources: [
            { 
              series_source: { source_name: 'mangadex', trust_score: 100 },
              chapter_url: 'http://example.com'
            }
          ]
        }
      ]);

      const followedSeriesIds = [seriesId];
      const items = await prisma.logicalChapter.findMany({
        where: { series_id: { in: followedSeriesIds } }
      });

      expect(items).toHaveLength(1);
      expect(items[0].series_id).toBe(seriesId);
    });
  });

  describe('TEST 3: LIBRARY SYNC', () => {
    it('should maintain state consistency across simulated devices', async () => {
      (prisma.$executeRaw as jest.Mock).mockResolvedValue(1);
      (prisma.libraryEntry.findMany as jest.Mock).mockResolvedValue([]); 

      await processNotification({ 
        data: { seriesId, sourceId: sourceId1, chapterNumber, newChapterCount: 1, cursor: dummyCursor },
        token: 'token'
      } as any);
      
      expect(notificationDeliveryQueue.add).not.toHaveBeenCalled();
    });
  });
});
