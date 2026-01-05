
import { Prisma } from '@prisma/client';

export type ActivityType = 
  | 'series_added' 
  | 'series_completed' 
  | 'chapter_read' 
  | 'achievement_unlocked'
  | 'follow'
  | 'status_updated';

/**
 * Logs an activity within a Prisma transaction
 */
export async function logActivity(
  tx: Prisma.TransactionClient,
  userId: string,
  type: ActivityType,
  data: {
    seriesId?: string;
    chapterId?: string;
    achievementId?: string;
    metadata?: any;
  }
) {
  return await tx.activity.create({
    data: {
      user_id: userId,
      type: type,
      series_id: data.seriesId,
      chapter_id: data.chapterId,
      achievement_id: data.achievementId,
      metadata: data.metadata || {},
    },
  });
}
