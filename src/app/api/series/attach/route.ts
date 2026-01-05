import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { prisma } from '@/lib/prisma';
import { syncSourceQueue } from '@/lib/queues';
import { handleApiError, ApiError, validateOrigin, checkRateLimit } from '@/lib/api-utils';
import { z } from 'zod';

const AttachSourceSchema = z.object({
  mangadex_id: z.string().uuid(),
  title: z.string().min(1).max(500),
  cover_url: z.string().url().max(2000).optional().nullable(),
  type: z.enum(['manga', 'manhwa', 'manhua', 'webtoon', 'comic', 'novel', 'light_novel']).optional().default('manga'),
  status: z.enum(['ongoing', 'completed', 'hiatus', 'cancelled', 'releasing', 'finished']).optional().nullable(),
  genres: z.array(z.string().max(50)).max(30).optional().default([]),
  description: z.string().max(10000).optional().nullable(),
});

/**
 * POST /api/series/attach
 * Lazy Attachment: Creates local series and source ONLY when requested.
 */
export async function POST(req: NextRequest) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      throw new ApiError('Unauthorized', 401);
    }

    // CSRF & Rate Limiting
    validateOrigin(req);
    if (!await checkRateLimit(`attach:${user.id}`, 10, 60000)) {
      throw new ApiError('Too many requests. Please wait.', 429);
    }

    let body;
    try {
      body = await req.json();
    } catch {
      throw new ApiError('Invalid JSON body', 400);
    }
    
    const parseResult = AttachSourceSchema.safeParse(body);
    if (!parseResult.success) {
      throw new ApiError(`Validation error: ${parseResult.error.errors[0].message}`, 400);
    }
    const validated = parseResult.data;

    // 1. Find or Create Series
    // We use mangadex_id as the unique identifier for canonical matching
    const series = await prisma.series.upsert({
      where: { mangadex_id: validated.mangadex_id },
      update: {
        // Update metadata if it changed
        title: validated.title,
        cover_url: validated.cover_url,
        status: validated.status,
        genres: validated.genres,
        description: validated.description,
      },
      create: {
        mangadex_id: validated.mangadex_id,
        title: validated.title,
        cover_url: validated.cover_url,
        type: validated.type,
        status: validated.status,
        genres: validated.genres,
        description: validated.description,
      },
    });

    // 2. Create SeriesSource (Lazy Attachment)
    const source = await prisma.seriesSource.upsert({
      where: {
        source_name_source_id: {
          source_name: 'mangadex',
          source_id: validated.mangadex_id,
        },
      },
      update: {
        series_id: series.id,
      },
      create: {
        series_id: series.id,
        source_name: 'mangadex',
        source_id: validated.mangadex_id,
        source_url: `https://mangadex.org/title/${validated.mangadex_id}`,
        source_title: validated.title,
        sync_priority: 'HOT', // Initial sync should be high priority
      },
    });

    // 3. Add to User's Library
    const libraryEntry = await prisma.libraryEntry.upsert({
      where: {
        user_id_series_id: {
          user_id: user.id,
          series_id: series.id,
        },
      },
      update: {
        status: 'reading',
      },
      create: {
        user_id: user.id,
        series_id: series.id,
        status: 'reading',
      },
    });

    // 4. Trigger Initial Sync Job
    await syncSourceQueue.add(`sync-${source.id}`, {
      seriesSourceId: source.id,
    }, {
      priority: 1, // High priority for first sync
      attempts: 3,
      backoff: { type: 'exponential', delay: 2000 },
    });

    // 5. Create Notifications & Emit Events (Phase-4)
    const supabaseAdminClient = (await import('@/lib/supabase/admin')).supabaseAdmin;
    
    // Series Available Notification
    await prisma.notification.create({
      data: {
        user_id: user.id,
        type: 'SERIES_AVAILABLE',
        title: 'Series Available',
        message: `"${series.title}" is now available in your library.`,
        series_id: series.id,
        metadata: {
          mangadex_id: validated.mangadex_id,
        }
      }
    });

    // Source Attached Notification
    await prisma.notification.create({
      data: {
        user_id: user.id,
        type: 'SOURCE_ATTACHED',
        title: 'Source Attached',
        message: `MangaDex source successfully attached to "${series.title}".`,
        series_id: series.id,
        metadata: {
          source_id: source.id,
          source_name: 'mangadex',
        }
      }
    });

    // Emit series.available event
    await supabaseAdminClient
      .channel('public:series')
      .send({
        type: 'broadcast',
        event: 'series.available',
        payload: {
          series_id: series.id,
          mangadex_id: validated.mangadex_id,
          title: series.title
        }
      });

    return NextResponse.json({
      success: true,
      series_id: series.id,
      library_entry_id: libraryEntry.id,
    }, { status: 201 });

  } catch (error) {
    return handleApiError(error);
  }
}
