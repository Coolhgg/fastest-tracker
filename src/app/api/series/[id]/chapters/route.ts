import { prisma, withRetry } from "@/lib/prisma"
import { NextRequest, NextResponse } from "next/server"
import { checkRateLimit, getClientIp, handleApiError, ApiError, ErrorCodes } from "@/lib/api-utils"
import { scrapers } from "@/lib/scrapers"
import { createClient } from "@/lib/supabase/server"
import { Prisma } from "@prisma/client"
import { syncChapters } from "@/lib/series-sync"

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const ip = getClientIp(request);
    if (!await checkRateLimit(`chapters:${ip}`, 60, 60000)) {
      throw new ApiError("Too many requests. Please wait a moment.", 429, ErrorCodes.RATE_LIMITED);
    }

    const { id } = await params
    const { searchParams } = new URL(request.url)
    const sourceFilter = searchParams.get("source")
    const sortBy = searchParams.get("sort") || "chapter_desc"
    const page = parseInt(searchParams.get("page") || "1")
    const limit = Math.min(parseInt(searchParams.get("limit") || "50"), 100)
    const grouped = searchParams.get("grouped") !== "false"

    if (!UUID_REGEX.test(id)) {
      throw new ApiError("Invalid series ID format", 400, ErrorCodes.VALIDATION_ERROR)
    }

    const supabase = await createClient()
    const { data: { user } } = await supabase.auth.getUser()

    // 1. Initial Fetch
    let { total, chapters } = await fetchChapters(id, {
      sourceFilter,
      sortBy,
      page,
      limit,
      grouped
    });

    // 2. On-demand Sync (If empty and first page)
    if (total === 0 && page === 1) {
      await performOnDemandSync(id);
      
      // Re-fetch after sync
      const refreshed = await fetchChapters(id, {
        sourceFilter,
        sortBy,
        page,
        limit,
        grouped
      });
      total = refreshed.total;
      chapters = refreshed.chapters;
    }

    // 3. User Read Status
    let readChapterIds: Set<string> = new Set()
    let lastReadChapter: number = -1

    if (user) {
      const [readChapters, libraryEntry] = await Promise.all([
        prisma.userChapterReadV2.findMany({
          where: {
            user_id: user.id,
            chapter: { series_id: id },
          },
          select: { chapter_id: true },
        }),
        prisma.libraryEntry.findUnique({
          where: {
            user_id_series_id: {
              user_id: user.id,
              series_id: id,
            },
          },
          select: { last_read_chapter: true },
        }),
      ])

      readChapterIds = new Set(readChapters.map(r => r.chapter_id))
      lastReadChapter = libraryEntry?.last_read_chapter ? Number(libraryEntry.last_read_chapter) : -1
    }

    // 4. Formatting
    const formattedChapters = chapters.map((c: any) => {
      const num = Number(c.chapter_number);
      const isRead = readChapterIds.has(c.id || c.chapter_id) || num <= lastReadChapter;
      
      if (grouped) {
        return {
          ...c,
          chapter_number: num,
          is_read: isRead,
          latest_upload: c.published_at?.toISOString() || c.first_seen_at?.toISOString() || null,
        };
      } else {
        return {
          ...c,
          chapter_number: num,
          is_read: isRead,
        };
      }
    });

    return NextResponse.json({
      chapters: formattedChapters,
      total,
      page,
      limit,
      total_pages: Math.ceil(total / limit),
      grouped,
    })
  } catch (error: unknown) {
    return handleApiError(error);
  }
}

async function fetchChapters(seriesId: string, options: any) {
  const { sourceFilter, sortBy, page, limit, grouped } = options;
  const skip = (page - 1) * limit;

  if (grouped) {
    const whereClause: Prisma.LogicalChapterWhereInput = { series_id: seriesId }
    const total = await prisma.logicalChapter.count({ where: whereClause })
    
    const logicalChapters = await withRetry(() => 
      prisma.logicalChapter.findMany({
        where: whereClause,
        orderBy: sortBy === "discovered_desc" 
          ? { first_seen_at: "desc" }
          : sortBy === "published_desc"
          ? { published_at: "desc" }
          : { chapter_number: "desc" },
        take: limit,
        skip,
          include: {
            sources: {
              where: sourceFilter ? {
                series_source: { source_name: sourceFilter }
              } : undefined,
              include: {
                series_source: {
                  select: {
                    id: true,
                    source_name: true,
                    source_id: true,
                    trust_score: true,
                  },
                },
              },
            },
          },
        })
      )
  
      return {
        total,
        chapters: logicalChapters.map(lc => ({
          id: lc.id,
          chapter_number: Number(lc.chapter_number),
          chapter_title: lc.chapter_title,
          volume_number: lc.volume_number,
          published_at: lc.published_at,
          first_seen_at: lc.first_seen_at,
          sources: lc.sources.map(s => ({
            id: s.id,
            source_name: s.series_source.source_name,
            source_id: s.series_source.source_id,
            chapter_url: s.chapter_url,
            published_at: s.source_published_at?.toISOString() || null,
            discovered_at: s.discovered_at.toISOString(),
            is_available: s.is_available,
            trust_score: Number(s.series_source.trust_score),
          })),
        }))
      };
    } else {
      const whereClause: Prisma.ChapterSourceWhereInput = {
        chapter: { series_id: seriesId },
        series_source: sourceFilter ? { source_name: sourceFilter } : undefined
      }
  
      const total = await prisma.chapterSource.count({ where: whereClause })
  
      const chapterSources = await withRetry(() =>
        prisma.chapterSource.findMany({
          where: whereClause,
          orderBy: sortBy === "discovered_desc"
            ? { discovered_at: "desc" }
            : sortBy === "published_desc"
            ? { source_published_at: "desc" }
            : { chapter: { chapter_number: "desc" } },
          take: limit,
          skip,
          include: {
            chapter: {
              select: {
                id: true,
                chapter_number: true,
                chapter_title: true,
                volume_number: true,
              }
            },
            series_source: {
              select: {
                id: true,
                source_name: true,
                source_id: true,
                trust_score: true,
              }
            }
          }
        })
      )
  
      return {
        total,
        chapters: chapterSources.map(s => ({
          id: s.id,
          chapter_id: s.chapter.id,
          chapter_number: Number(s.chapter.chapter_number),
          chapter_title: s.chapter_title || s.chapter.chapter_title,
          volume_number: s.chapter.volume_number,
          chapter_url: s.chapter_url,
          published_at: s.source_published_at?.toISOString() || null,
          discovered_at: s.discovered_at.toISOString(),
          is_available: s.is_available,
          source_name: s.series_source.source_name,
          source_id: s.series_source.source_id,
          trust_score: Number(s.series_source.trust_score),
        }))
      };

  }
}

async function performOnDemandSync(seriesId: string) {
  // Use a session-level advisory lock to prevent concurrent scrapes
  // but WITHOUT holding a database transaction open during the network call
  const lockId = parseInt(seriesId.replace(/-/g, '').substring(0, 8), 16)
  
  try {
    // Try to acquire lock. If already locked, skip sync (another request is doing it)
    const lockAcquired = await prisma.$queryRawUnsafe<{ pg_try_advisory_lock: boolean }[]>(
      `SELECT pg_try_advisory_lock(${lockId})`
    );

    if (!lockAcquired[0].pg_try_advisory_lock) {
      console.log(`[Sync] Series ${seriesId} is already being synced, skipping.`);
      return;
    }

    try {
      // Check again if we still need to sync (double-checked locking)
      const currentCount = await prisma.logicalChapter.count({ where: { series_id: seriesId } });
      if (currentCount > 0) return;

      const series = await prisma.series.findUnique({
        where: { id: seriesId },
        include: { sources: true }
      });

      if (!series || series.sources.length === 0) return;

      // Pick the best source to sync
      const source = series.sources.find(s => s.source_name === 'mangadex') || series.sources[0];
      
      if (scrapers[source.source_name]) {
        console.log(`[Sync] Performing on-demand sync for ${series.title} via ${source.source_name}`);
        const scraped = await scrapers[source.source_name].scrapeSeries(source.source_id);
        
        if (scraped.chapters.length > 0) {
          await syncChapters(seriesId, source.source_id, source.source_name, scraped.chapters);
        }
      }
    } finally {
      // Always release the lock
      await prisma.$executeRawUnsafe(`SELECT pg_advisory_unlock(${lockId})`);
    }
  } catch (err) {
    console.error(`[Sync] On-demand sync failed for ${seriesId}:`, err);
  }
}
