import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { prisma } from '@/lib/prisma';
import { logActivity } from '@/lib/gamification/activity';
import { XP_PER_CHAPTER, calculateLevel, addXp } from '@/lib/gamification/xp';
import { calculateNewStreak, calculateStreakBonus } from '@/lib/gamification/streaks';
import { checkAchievements } from '@/lib/gamification/achievements';
import { validateUUID, checkRateLimit, handleApiError, ApiError, validateOrigin, ErrorCodes, getClientIp } from '@/lib/api-utils';
import { z } from 'zod';

const progressSchema = z.object({
  chapterNumber: z.number().min(0).max(100000).finite(),
  sourceId: z.string().uuid().optional(),
});

/**
 * PATCH /api/library/[id]/progress
 * Marks a chapter as read, updates streak and XP
 */
export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // CSRF Protection
    validateOrigin(req);

    // Rate limit: 60 progress updates per minute per IP
    const ip = getClientIp(req);
    if (!await checkRateLimit(`progress-update:${ip}`, 60, 60000)) {
      throw new ApiError('Too many requests. Please wait a moment.', 429, ErrorCodes.RATE_LIMITED);
    }

    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      throw new ApiError('Unauthorized', 401, ErrorCodes.UNAUTHORIZED);
    }

    const { id: entryId } = await params;

    // Validate UUID format
    validateUUID(entryId, 'entryId');

    let body;
    try {
      body = await req.json();
    } catch {
      throw new ApiError('Invalid JSON body', 400, ErrorCodes.BAD_REQUEST);
    }

    // Validate request body
    const validatedData = progressSchema.safeParse(body);
    if (!validatedData.success) {
      throw new ApiError(validatedData.error.errors[0].message, 400, ErrorCodes.VALIDATION_ERROR);
    }

    const { chapterNumber, sourceId } = validatedData.data;

    const result = await prisma.$transaction(async (tx) => {
      // 1. Get current entry and user profile
      const entry = await tx.libraryEntry.findUnique({
        where: { id: entryId, user_id: user.id },
        include: { series: true }
      });

      if (!entry) {
        throw new ApiError('Library entry not found', 404, ErrorCodes.NOT_FOUND);
      }

      // Check if trying to mark an older chapter as read
      const currentLastRead = Number(entry.last_read_chapter || 0);
      const isNewChapter = chapterNumber > currentLastRead;

      const userProfile = await tx.user.findUnique({
        where: { id: user.id },
      });

      if (!userProfile) {
        throw new ApiError('User profile not found', 404, ErrorCodes.NOT_FOUND);
      }

      // 2. Identify Logical Chapter
      const logicalChapter = await tx.logicalChapter.findUnique({
        where: {
          series_id_chapter_number: {
            series_id: entry.series_id,
            chapter_number: chapterNumber,
          }
        },
        select: { id: true }
      });

      // 3. Check for existing read (Idempotency / Replay-safety)
      // If we already have a record for this chapter, don't award XP again
      let alreadyRead = false;
      if (logicalChapter) {
        const existingRead = await tx.userChapterReadV2.findUnique({
          where: {
            user_id_chapter_id: {
              user_id: user.id,
              chapter_id: logicalChapter.id,
            }
          }
        });
        alreadyRead = !!existingRead;
      }

      // 4. Calculate new streak and XP
      const newStreak = calculateNewStreak(userProfile.streak_days, userProfile.last_read_at);
      const streakBonus = calculateStreakBonus(newStreak);
      
      // Award XP ONLY if it's a new chapter and NOT already read (handles retries)
      const shouldAwardXp = isNewChapter && !alreadyRead;
      const totalXpGained = shouldAwardXp ? (XP_PER_CHAPTER + streakBonus) : 0;

      // 5. Update Library Entry
      const updatedEntry = await tx.libraryEntry.update({
        where: { id: entryId },
        data: {
          last_read_chapter: isNewChapter ? chapterNumber : entry.last_read_chapter,
          last_read_at: new Date(),
        },
      });

      // 6. Update User Profile (XP, Level, Streak)
      const newXp = addXp(userProfile.xp || 0, totalXpGained);
      const newLevel = calculateLevel(newXp);
      const longestStreak = Math.max(userProfile.longest_streak || 0, newStreak);

      await tx.user.update({
        where: { id: user.id },
        data: {
          xp: newXp,
          level: newLevel,
          streak_days: newStreak,
          longest_streak: longestStreak,
          last_read_at: new Date(),
          chapters_read: { increment: shouldAwardXp ? 1 : 0 },
        },
      });

      // 7. Log Activity (Only if new XP awarded or first read)
      if (shouldAwardXp || !alreadyRead) {
        await logActivity(tx, user.id, 'chapter_read', {
          seriesId: entry.series_id,
          metadata: { 
            chapter_number: chapterNumber,
            xp_gained: totalXpGained,
            streak: newStreak
          },
        });
      }

        // 8. Record Chapter Read (Fix for progress saving issue)
        // Find all chapters with this number for this series across all sources
        const chapters = await tx.chapter.findMany({
          where: {
            series_id: entry.series_id,
            chapter_number: chapterNumber,
          },
          select: { id: true }
        });

        if (chapters.length > 0) {
          // PERF M6: Use transaction-safe sequential execution or batching
          // Since we are in a transaction, we can just run them sequentially or use a loop
          for (const ch of chapters) {
            await tx.userChapterRead.upsert({
              where: {
                user_id_chapter_id: {
                  user_id: user.id,
                  chapter_id: ch.id,
                },
              },
              create: {
                user_id: user.id,
                chapter_id: ch.id,
              },
              update: {
                read_at: new Date(),
              },
            });
          }
        }

        // Also handle LogicalChapters (V2)
        if (logicalChapter) {
          const sourceData = sourceId ? {
            source_used_id: sourceId
          } : {};

          await tx.userChapterReadV2.upsert({
            where: {
              user_id_chapter_id: {
                user_id: user.id,
                chapter_id: logicalChapter.id,
              },
            },
            create: {
              user_id: user.id,
              chapter_id: logicalChapter.id,
              ...sourceData
            },
            update: {
              read_at: new Date(),
              ...sourceData
            },
          });
        }

      // 7. Check Achievements
      await checkAchievements(tx, user.id, 'chapter_read');
      if (newStreak > userProfile.streak_days) {
        await checkAchievements(tx, user.id, 'streak_reached');
      }

      return {
        entry: updatedEntry,
        xp_gained: totalXpGained,
        new_streak: newStreak,
        new_level: newLevel
      };
    });

    return NextResponse.json(result);
  } catch (error: any) {
    console.error('Progress update error:', error);
    return handleApiError(error);
  }
}
