import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { supabaseAdmin } from '@/lib/supabase/admin';
import { prisma } from '@/lib/prisma';
import { sanitizeInput, checkRateLimit, handleApiError, ApiError, ErrorCodes, validateOrigin, escapeILikePattern, getClientIp } from '@/lib/api-utils';
import { z } from 'zod';
import { isValidCoverUrl } from '@/lib/cover-resolver';

const AddToLibrarySchema = z.object({
  seriesId: z.string().uuid('Invalid series ID format'),
  status: z.enum(['reading', 'completed', 'planning', 'dropped', 'paused']).default('reading'),
});

const LibraryQuerySchema = z.object({
  q: z.string().optional(),
  status: z.string().optional(),
  sort: z.enum(['updated', 'title', 'rating', 'added']).default('updated'),
  limit: z.coerce.number().min(1).max(200).default(100),
  offset: z.coerce.number().min(0).default(0),
});

/**
 * GET /api/library
 * Returns the user's library entries with filtering and sorting
 */
export async function GET(req: NextRequest) {
  try {
    const ip = getClientIp(req);
    if (!await checkRateLimit(`library-get:${ip}`, 60, 60000)) {
      throw new ApiError('Too many requests. Please wait a moment.', 429, ErrorCodes.RATE_LIMITED);
    }

    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      throw new ApiError('Unauthorized', 401, ErrorCodes.UNAUTHORIZED);
    }

    const searchParams = Object.fromEntries(req.nextUrl.searchParams);
    const validatedParams = LibraryQuerySchema.safeParse(searchParams);
    
    if (!validatedParams.success) {
      throw new ApiError(validatedParams.error.errors[0].message, 400, ErrorCodes.VALIDATION_ERROR);
    }

    const { q: query, status, sort: sortBy, limit, offset } = validatedParams.data;

    const entries = await prisma.libraryEntry.findMany({
      where: {
        user_id: user.id,
        status: status && status !== 'all' ? (status as any) : undefined,
        series: query && query.length >= 2 ? {
          title: { contains: query, mode: 'insensitive' }
        } : undefined,
      },
      include: {
        series: {
          select: {
            id: true,
            title: true,
            cover_url: true,
            best_cover_url: true,
            type: true,
            status: true,
            content_rating: true,
            latest_chapter: true,
            last_chapter_at: true,
          }
        }
      },
      orderBy: sortBy === 'title' 
        ? { series: { title: 'asc' } } 
        : sortBy === 'rating' 
        ? { user_rating: 'desc' }
        : sortBy === 'added'
        ? { added_at: 'desc' }
        : { updated_at: 'desc' },
      take: limit,
      skip: offset,
    });

    const totalCount = await prisma.libraryEntry.count({
      where: {
        user_id: user.id,
        status: status && status !== 'all' ? (status as any) : undefined,
        series: query && query.length >= 2 ? {
          title: { contains: query, mode: 'insensitive' }
        } : undefined,
      }
    });

    // Get counts for each status for the UI counters
    const statusCounts = await prisma.libraryEntry.groupBy({
      by: ['status'],
      where: {
        user_id: user.id,
        series: query && query.length >= 2 ? {
          title: { contains: query, mode: 'insensitive' }
        } : undefined,
      },
      _count: {
        _all: true
      }
    });

    const stats = {
      all: statusCounts.reduce((acc, curr) => acc + curr._count._all, 0),
      reading: statusCounts.find(s => s.status === 'reading')?._count._all || 0,
      completed: statusCounts.find(s => s.status === 'completed')?._count._all || 0,
      planning: statusCounts.find(s => s.status === 'planning')?._count._all || 0,
      dropped: statusCounts.find(s => s.status === 'dropped')?._count._all || 0,
      paused: statusCounts.find(s => s.status === 'paused')?._count._all || 0,
    };

    // Format response - much lighter now without source joins
    const formattedEntries = entries.map((entry) => {
      if (!entry.series) return entry;

      const coverUrl = entry.series.best_cover_url || 
        (isValidCoverUrl(entry.series.cover_url) ? entry.series.cover_url : null);
      
      return {
        ...entry,
        series: {
          ...entry.series,
          cover_url: coverUrl,
          latest_chapter: entry.series.latest_chapter ? Number(entry.series.latest_chapter) : null,
        },
      };
    });

    return NextResponse.json({ 
      entries: formattedEntries,
      stats,
      pagination: {
        total: totalCount,
        limit,
        offset,
        hasMore: offset + entries.length < totalCount
      }
    });
  } catch (error: any) {
    console.error('Library fetch error:', error);
    return handleApiError(error);
  }
}

/**
 * POST /api/library
 * Adds a series to the user's library
 */
export async function POST(req: NextRequest) {
  try {
    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      throw new ApiError('Unauthorized', 401, ErrorCodes.UNAUTHORIZED);
    }

    validateOrigin(req);

    if (!await checkRateLimit(`library-add:${user.id}`, 30, 60000)) {
      throw new ApiError('Too many requests. Please wait a moment.', 429, ErrorCodes.RATE_LIMITED);
    }

    let body;
    try {
      body = await req.json();
    } catch {
      throw new ApiError('Invalid JSON body', 400, ErrorCodes.BAD_REQUEST);
    }
    
    const validatedBody = AddToLibrarySchema.safeParse(body);
    if (!validatedBody.success) {
      throw new ApiError(validatedBody.error.errors[0].message, 400, ErrorCodes.VALIDATION_ERROR);
    }

    const { seriesId, status } = validatedBody.data;

    // Check if series exists
    const series = await prisma.series.findUnique({
      where: { id: seriesId },
      select: { id: true }
    });

    if (!series) {
      throw new ApiError('Series not found', 404, ErrorCodes.NOT_FOUND);
    }

    // Create library entry
    const existingEntry = await prisma.libraryEntry.findUnique({
      where: {
        user_id_series_id: {
          user_id: user.id,
          series_id: seriesId,
        }
      },
      select: { id: true }
    });

    const entry = await prisma.libraryEntry.upsert({
      where: {
        user_id_series_id: {
          user_id: user.id,
          series_id: seriesId,
        }
      },
      update: {
        status: status,
      },
      create: {
        user_id: user.id,
        series_id: seriesId,
        status: status,
        last_read_chapter: 0,
      }
    });

    // Increment follow count only for NEW entries (async)
    if (!existingEntry) {
      prisma.series.update({
        where: { id: seriesId },
        data: { total_follows: { increment: 1 } }
      }).catch(e => console.error('Failed to increment follows:', e));
    }
    
    return NextResponse.json(entry, { status: 201 });

  } catch (error: any) {
    console.error('Library add error:', error);
    return handleApiError(error);
  }
}
