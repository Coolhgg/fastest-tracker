import { Job } from 'bullmq';
import { prisma } from '@/lib/prisma';
import { syncSourceQueue } from '@/lib/queues';
import { z } from 'zod';
import { Prisma } from '@prisma/client';

const GapRecoveryDataSchema = z.object({
  seriesId: z.string().uuid(),
});

export interface GapRecoveryData {
  seriesId: string;
}

/**
 * Gap Recovery Processor
 * 
 * Detects missing chapters in a series and triggers re-polling of sources
 * to fill the gaps.
 */
export async function processGapRecovery(job: Job<GapRecoveryData>) {
  const parseResult = GapRecoveryDataSchema.safeParse(job.data);
  if (!parseResult.success) {
    throw new Error(`Invalid job payload: ${parseResult.error.message}`);
  }

  const { seriesId } = parseResult.data;

  // 1. Find all chapters for this series to detect gaps
  const chapters = await prisma.logicalChapter.findMany({
    where: { series_id: seriesId },
    select: { chapter_number: true },
    orderBy: { chapter_number: 'asc' },
  });

  if (chapters.length <= 1) {
    return { status: 'skipped', reason: 'Not enough chapters to detect gaps' };
  }

  const gaps: number[] = [];
  for (let i = 0; i < chapters.length - 1; i++) {
    const current = chapters[i].chapter_number.toNumber();
    const next = chapters[i + 1].chapter_number.toNumber();
    
    // If the difference is greater than 1, we have a gap
    // Note: We only handle integer gaps for now as most manga follows integer numbering
    if (next - current > 1) {
      for (let missing = current + 1; missing < next; missing++) {
        gaps.push(missing);
      }
    }
  }

  if (gaps.length === 0) {
    return { status: 'completed', message: 'No gaps detected' };
  }

  console.log(`[GapRecovery] Detected ${gaps.length} missing chapters for series ${seriesId}: ${gaps.slice(0, 10).join(', ')}${gaps.length > 10 ? '...' : ''}`);

  // 2. Trigger re-poll of all active sources for this series
  const sources = await prisma.seriesSource.findMany({
    where: { 
      series_id: seriesId,
      is_active: true 
    },
    select: { id: true }
  });

  for (const source of sources) {
    // Add to syncSourceQueue which triggers processPollSource
    await syncSourceQueue.add(
      `gap-fill-${source.id}-${Date.now()}`,
      { seriesSourceId: source.id },
      { 
        priority: 5, // Lower priority than fresh releases
        attempts: 1 
      }
    );
  }

  return { 
    status: 'triggered', 
    gapCount: gaps.length, 
    sourceCount: sources.length 
  };
}
