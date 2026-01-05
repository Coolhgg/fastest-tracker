import { supabaseAdmin } from "@/lib/supabase/admin"
import { NextRequest, NextResponse } from "next/server"
import { checkRateLimit, handleApiError, getClientIp } from "@/lib/api-utils"
import { getBestCoversBatch, isValidCoverUrl } from "@/lib/cover-resolver"

const VALID_PERIODS = ['day', 'week', 'month', 'all'] as const
const VALID_TYPES = ['manga', 'manhwa', 'manhua', 'webtoon'] as const

export async function GET(request: NextRequest) {
  // Rate limit: 60 requests per minute per IP
  const ip = getClientIp(request);
  if (!await checkRateLimit(`trending:${ip}`, 60, 60000)) {
    return NextResponse.json(
      { error: 'Too many requests. Please wait a moment.' },
      { status: 429 }
    )
  }

  const searchParams = request.nextUrl.searchParams
  const period = searchParams.get('period') || 'week'
  const type = searchParams.get('type')
  const limit = Math.min(Math.max(1, parseInt(searchParams.get('limit') || '20')), 50)
  const offset = Math.max(0, parseInt(searchParams.get('offset') || '0'))

  // Validate period
  if (!VALID_PERIODS.includes(period as any)) {
    return NextResponse.json(
      { error: 'Invalid period. Must be one of: day, week, month, all' },
      { status: 400 }
    )
  }

  // Validate type if provided
  if (type && !VALID_TYPES.includes(type as any)) {
    return NextResponse.json(
      { error: 'Invalid type. Must be one of: manga, manhwa, manhua, webtoon' },
      { status: 400 }
    )
  }

  try {
    // First, get series with their chapter counts
    let query = supabaseAdmin
      .from('series')
      .select(`
        id,
        title,
        cover_url,
        content_rating,
        type,
        status,
        genres,
        total_follows,
        total_views,
        average_rating,
        updated_at
      `, { count: 'exact' })

    if (type) {
      query = query.eq('type', type)
    }

    // Order by popularity and recency
    const { data: seriesData, count, error } = await query
      .order('total_follows', { ascending: false })
      .order('updated_at', { ascending: false })
      .range(offset, offset + limit - 1)

    if (error) {
      console.error('Trending query error:', error)
      return NextResponse.json(
        { error: 'Failed to fetch trending series' },
        { status: 500 }
      )
    }

    // Get chapter counts for each series
    const seriesIds = (seriesData || []).map(s => s.id)
    
    let chaptersData: any[] = []
    if (seriesIds.length > 0) {
      const { data: chapters } = await supabaseAdmin
        .from('chapters')
        .select('series_id, chapter_number, chapter_title, published_at, discovered_at')
        .in('series_id', seriesIds)
        .order('chapter_number', { ascending: false })

      chaptersData = chapters || []
    }

    // Group chapters by series
    const chaptersBySeries = new Map<string, any[]>()
    for (const ch of chaptersData) {
      if (!chaptersBySeries.has(ch.series_id)) {
        chaptersBySeries.set(ch.series_id, [])
      }
      chaptersBySeries.get(ch.series_id)!.push(ch)
    }

    // If filtering by period, filter series that have chapters in that period
    let filteredSeries = seriesData || []
    if (period !== 'all') {
      const now = new Date()
      let cutoffDate: Date
      
      switch (period) {
        case 'day':
          cutoffDate = new Date(now.getTime() - 24 * 60 * 60 * 1000)
          break
        case 'week':
          cutoffDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)
          break
        case 'month':
          cutoffDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000)
          break
        default:
          cutoffDate = new Date(0)
      }

      filteredSeries = filteredSeries.filter(s => {
          const chapters = chaptersBySeries.get(s.id) || []
          return chapters.some(ch => new Date(ch.discovered_at) >= cutoffDate)
        })
      }

      // Resolve best covers from series_sources
      const seriesIdsForCovers = filteredSeries.map((s: any) => s.id)
      const bestCovers = await getBestCoversBatch(seriesIdsForCovers)

        return NextResponse.json({
          results: filteredSeries.map((s: any) => {
            const chapters = chaptersBySeries.get(s.id) || []
            const bestCover = bestCovers.get(s.id)
            const fallbackCover = isValidCoverUrl(s.cover_url) ? s.cover_url : null
            return {
              id: s.id,
              title: s.title,
              cover_url: bestCover?.cover_url || fallbackCover,
              content_rating: s.content_rating,
              type: s.type,
              status: s.status,
              genres: s.genres,
              total_follows: s.total_follows,
              total_views: s.total_views,
              average_rating: s.average_rating,
              chapter_count: chapters.length,
              latest_chapter: chapters[0] || null,
              updated_at: s.updated_at
            }
          }),
      total: filteredSeries.length,
      limit,
      offset,
      period,
      has_more: offset + filteredSeries.length < (count || 0)
    })

  } catch (error: any) {
    console.error('Trending error:', error)
    return handleApiError(error)
  }
}
