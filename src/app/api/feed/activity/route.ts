import { prisma } from "@/lib/prisma"
import { NextRequest, NextResponse } from "next/server"
import { checkRateLimit, getClientIp, handleApiError, ApiError, ErrorCodes } from "@/lib/api-utils"
import { createClient } from "@/lib/supabase/server"

interface SourceEntry {
  name: string;
  url: string;
  discovered_at: string;
}

interface FeedEntryRow {
  id: string;
  series_id: string;
  logical_chapter_id: string | null;
  chapter_number: string;
  sources: SourceEntry[];
  first_discovered_at: Date;
  last_updated_at: Date;
  series_title: string;
  series_cover_url: string | null;
  series_content_rating: string | null;
  series_status: string | null;
  series_type: string;
  chapter_title: string | null;
  volume_number: number | null;
  published_at: Date | null;
}

export async function GET(request: NextRequest) {
  try {
    const ip = getClientIp(request);
    if (!await checkRateLimit(`feed-activity:${ip}`, 60, 60000)) {
      throw new ApiError("Too many requests. Please wait a moment.", 429, ErrorCodes.RATE_LIMITED);
    }

      const { searchParams } = new URL(request.url);
      const cursor = searchParams.get("cursor");
      const limit = Math.min(parseInt(searchParams.get("limit") || "30"), 100);
      const seriesId = searchParams.get("series_id");
      const unseenOnly = searchParams.get("unseen_only") === "true";

      const supabase = await createClient();
      const { data: { user } } = await supabase.auth.getUser();

      let feedLastSeenAt: Date | null = null;
      if (user) {
        const dbUser = await prisma.user.findUnique({
          where: { id: user.id },
          select: { feed_last_seen_at: true }
        });
        
        if (dbUser?.feed_last_seen_at) {
          feedLastSeenAt = dbUser.feed_last_seen_at;
        } else {
          // First visit: treat all activity within the last 7 days as "New"
          feedLastSeenAt = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        }
      }

      const cursorDate = cursor ? new Date(cursor) : null;

      const params: (string | number | Date)[] = [];
      let paramIndex = 1;
      
      let whereClause = "WHERE 1=1";
      if (seriesId) {
        whereClause += ` AND fe.series_id = $${paramIndex}::uuid`;
        params.push(seriesId);
        paramIndex++;
      }
      if (cursorDate) {
        whereClause += ` AND fe.first_discovered_at < $${paramIndex}`;
        params.push(cursorDate);
        paramIndex++;
      }
      if (unseenOnly && feedLastSeenAt) {
        whereClause += ` AND fe.first_discovered_at > $${paramIndex}`;
        params.push(feedLastSeenAt);
        paramIndex++;
      }


    params.push(limit + 1);

    const feedEntries = await prisma.$queryRawUnsafe<FeedEntryRow[]>(`
      SELECT 
        fe.id,
        fe.series_id,
        fe.logical_chapter_id,
        fe.chapter_number::text,
        fe.sources,
        fe.first_discovered_at,
        fe.last_updated_at,
        s.title as series_title,
        s.cover_url as series_cover_url,
        s.content_rating as series_content_rating,
        s.status as series_status,
        s.type as series_type,
        lc.chapter_title,
        lc.volume_number,
        lc.published_at
      FROM feed_entries fe
      JOIN series s ON s.id = fe.series_id
      LEFT JOIN logical_chapters lc ON lc.id = fe.logical_chapter_id
      ${whereClause}
      ORDER BY fe.first_discovered_at DESC
      LIMIT $${paramIndex}
    `, ...params);

    const hasMore = feedEntries.length > limit;
    const items = hasMore ? feedEntries.slice(0, -1) : feedEntries;
    const nextCursor = hasMore && items.length > 0 
      ? new Date(items[items.length - 1].first_discovered_at).toISOString() 
      : null;

    return NextResponse.json({
      entries: items.map((entry) => ({
        id: entry.id,
        series: {
          id: entry.series_id,
          title: entry.series_title,
          cover_url: entry.series_cover_url,
          content_rating: entry.series_content_rating,
          status: entry.series_status,
          type: entry.series_type,
        },
        chapter_number: Number(entry.chapter_number),
        chapter_title: entry.chapter_title,
        volume_number: entry.volume_number,
        is_unseen: feedLastSeenAt ? new Date(entry.first_discovered_at) > feedLastSeenAt : true,
        sources: (entry.sources || []).map(s => ({
          name: s.name,
          url: s.url,
          discovered_at: s.discovered_at,
        })),
        first_discovered_at: new Date(entry.first_discovered_at).toISOString(),
        last_updated_at: new Date(entry.last_updated_at).toISOString(),
      })),
      next_cursor: nextCursor,
      has_more: hasMore,
    });
  } catch (error) {
    return handleApiError(error);
  }
}
