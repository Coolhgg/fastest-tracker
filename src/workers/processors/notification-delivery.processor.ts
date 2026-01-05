import { Job } from 'bullmq';
import { prisma } from '@/lib/prisma';
import { shouldThrottleUser } from '@/lib/notifications-throttling';
import { getNotificationSystemHealth } from '@/lib/queues';
import { z } from 'zod';

const NotificationDeliveryDataSchema = z.object({
  seriesId: z.string().uuid(),
  sourceId: z.string().uuid(),
  sourceName: z.string().optional(),
  chapterNumber: z.number(),
  newChapterCount: z.number().int().positive(),
  userIds: z.array(z.string().uuid()),
  isPremium: z.boolean().default(false),
  priority: z.number().int().min(0).max(2).default(2),
});

export type NotificationDeliveryData = z.infer<typeof NotificationDeliveryDataSchema>;

/**
 * Delivery Processor
 * 1. Implements Circuit Breakers based on system health.
 * 2. Checks per-user and per-manga throttling.
 * 3. Creates notifications in the DB.
 * 4. Gracefully degrades (Lite Mode) under load.
 */
export async function processNotificationDelivery(job: Job<NotificationDeliveryData>) {
  const parseResult = NotificationDeliveryDataSchema.safeParse(job.data);
  if (!parseResult.success) {
    console.error(`[Notification-Delivery] Invalid payload: ${parseResult.error.message}`);
    return;
  }

    const { seriesId, sourceId, sourceName, chapterNumber, newChapterCount, userIds, isPremium, priority } = parseResult.data;


  // 1. Circuit Breaker / Overload Check
  const health = await getNotificationSystemHealth();
  
  if (health.isRejected && !isPremium) {
    console.error(`[Notification-Delivery] CIRCUIT BREAKER: System at capacity (${health.totalWaiting} waiting). Rejecting free job.`);
    return;
  }

  if (health.isOverloaded) {
    console.warn(`[Notification-Delivery] System overloaded (${health.totalWaiting} waiting). Applying 5s throttle delay.`);
    await new Promise(resolve => setTimeout(resolve, 5000));
  }

  const isLiteMode = health.isCritical; // Skip metadata if > 50K jobs
  if (isLiteMode) {
    console.warn(`[Notification-Delivery] LITE MODE ENABLED: Skipping metadata and detailed messages due to backlog.`);
  }

  const series = await prisma.series.findUnique({
    where: { id: seriesId },
    select: { title: true }
  });

  if (!series) {
    console.warn(`[Notification-Delivery] Series ${seriesId} not found, skipping batch`);
    return;
  }

    const notificationsToCreate = [];

    // 2. Fetch existing notifications to prevent duplicates and implement priority suppression
    const existingNotifications = await prisma.notification.findMany({
      where: {
        user_id: { in: userIds },
        series_id: seriesId,
        type: 'NEW_CHAPTER',
        metadata: {
          path: ['chapter_number'],
          equals: chapterNumber
        }
      },
      select: { user_id: true, priority: true, id: true }
    });

    const userNotificationMap = new Map<string, { priority: number, id: string }>();
    existingNotifications.forEach(n => {
      userNotificationMap.set(n.user_id, { priority: n.priority ?? 2, id: n.id });
    });

    // ...

    const notificationsToDelete: string[] = [];

      for (const userId of userIds) {
        const existing = userNotificationMap.get(userId);
        
        // Suppression Logic:
        // 1. If higher or equal priority already exists, skip creating the new one
        if (existing && existing.priority <= priority) {
          continue;
        }

        // 2. If lower priority exists, we'll replace it with the new higher priority one
        if (existing && existing.priority > priority) {
          notificationsToDelete.push(existing.id);
        }

        // Check throttling
        const { throttle, reason } = await shouldThrottleUser(userId, seriesId, isPremium);
      
      if (throttle) {
        console.log(`[Notification-Delivery] Throttled user ${userId} for series ${seriesId}. Reason: ${reason}`);
        continue;
      }

        notificationsToCreate.push({
          user_id: userId,
          type: 'NEW_CHAPTER',
          title: 'New Chapter Available',
          message: isLiteMode 
            ? `New update for ${series.title}`
            : `${newChapterCount} new chapter${newChapterCount > 1 ? 's' : ''} for "${series.title}"${sourceName ? ` on ${sourceName}` : ''}!`,
          series_id: seriesId,
          priority: priority,
          metadata: {
          source_id: sourceId,
          source_name: sourceName,
          chapter_count: newChapterCount,
          chapter_number: chapterNumber, // Added for idempotency check
          delivery_job_id: job.id,
          is_lite: isLiteMode
        }
      });
    }


  if (notificationsToDelete.length > 0) {
    await prisma.notification.deleteMany({
      where: { id: { in: notificationsToDelete } }
    });
    console.log(`[Notification-Delivery] Suppressed/Deleted ${notificationsToDelete.length} lower priority notifications`);
  }

  if (notificationsToCreate.length > 0) {
    try {
      await prisma.notification.createMany({
        data: notificationsToCreate,
      });
      console.log(`[Notification-Delivery] Created ${notificationsToCreate.length} notifications for "${series.title}"${isLiteMode ? ' (Lite Mode)' : ''}`);
    } catch (error) {
      console.error(`[Notification-Delivery] DB Write Failure:`, error);
      // BullMQ will automatically retry the job based on the queue's defaultJobOptions.
      throw error; 
    }
  } else {
    console.log(`[Notification-Delivery] No notifications created for batch in "${series.title}" (all throttled or suppressed)`);
  }
}
