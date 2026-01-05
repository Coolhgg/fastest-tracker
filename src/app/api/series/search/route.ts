import { supabaseAdminRead } from "@/lib/supabase/admin"
import { createClient } from "@/lib/supabase/server"
import { NextRequest, NextResponse } from "next/server"
import { checkRateLimit, sanitizeInput, handleApiError, ApiError, ErrorCodes, getClientIp } from "@/lib/api-utils"
import { checkSourceQueue, isQueueHealthy } from "@/lib/queues"
import { areWorkersOnline, redis, waitForRedis, REDIS_KEY_PREFIX } from "@/lib/redis"
import { detectSearchIntent } from "@/lib/search-intent"
import { recordSearchEvent } from "@/lib/analytics"
import { getBestCoversBatch, isValidCoverUrl } from "@/lib/cover-resolver"
import { FilterSchema, CanonicalFilter } from "@/lib/schemas/filters"
import { FILTER_PARAMS, DEPRECATED_PARAMS } from "@/lib/constants/filters"
import { 
  buildSeriesQuery, 
  createSearchCursor,
  getSeriesIdsWithMultipleSources,
  stripSourcesFromResults
} from "@/lib/api/search-query"
import { prisma } from "@/lib/prisma"
import {
  getCachedSearchResult,
  setCachedSearchResult,
  checkPendingSearch,
  markSearchPending,
  clearPendingSearch,
  waitForPendingSearch,
  checkExternalSearchDedup,
  markExternalSearchPending,
  updateQueryHeat,
  getQueryHeat,
  deferSearchQuery,
  SEARCH_PRIORITY,
  getPremiumQuota,
  incrementPremiumQuota,
  getPremiumConcurrency,
  incrementPremiumConcurrency,
} from "@/lib/search-cache"

// Valid source values (lowercase in DB)
const VALID_SOURCES = new Set([
  'all', 'mangadex', 'mangapark', 'mangasee', 'comick', 'multiple'
])

/**
 * Get parameter value with deprecation warning support
 */
function getParam(
  searchParams: URLSearchParams,
  canonicalKey: keyof typeof FILTER_PARAMS
): string | null {
  const P = FILTER_PARAMS
  const canonicalName = P[canonicalKey]
  
  const canonicalValue = searchParams.get(canonicalName)
  if (canonicalValue !== null) {
    return canonicalValue
  }
  
  for (const [deprecated, canonical] of Object.entries(DEPRECATED_PARAMS)) {
    if (canonical === canonicalKey) {
      const deprecatedValue = searchParams.get(deprecated)
      if (deprecatedValue !== null) {
        console.warn(`[Search API] Deprecated param '${deprecated}' used. Use '${canonicalName}' instead.`)
        return deprecatedValue
      }
    }
  }
  
  return null
}

  export async function GET(request: NextRequest) {
    const startTime = Date.now()
    const ip = getClientIp(request)
    const P = FILTER_PARAMS
  
    try {
      if (!await checkRateLimit(`search:${ip}`, 60, 60000)) {
        throw new ApiError("Too many requests", 429, ErrorCodes.RATE_LIMITED)
      }

      const searchParams = request.nextUrl.searchParams
      const intentParam = searchParams.get('intent')
      
      // Parse using canonical params with deprecation fallback
      const rawFilters: any = {
        q: getParam(searchParams, 'query'),
        type: getParam(searchParams, 'types')?.split(',').filter(Boolean) || [],
        genres: searchParams.get(P.genres)?.split(',').filter(Boolean) || [],
        tags: getParam(searchParams, 'themes')?.split(',').filter(Boolean) || [],
        themes: getParam(searchParams, 'themes')?.split(',').filter(Boolean) || [],
        contentWarnings: {
          include: getParam(searchParams, 'includeWarnings')?.split(',').filter(Boolean) || [],
          exclude: getParam(searchParams, 'excludeWarnings')?.split(',').filter(Boolean) || [],
        },
        publicationStatus: getParam(searchParams, 'status')?.split(',').filter(Boolean) || [],
        contentRating: getParam(searchParams, 'rating')?.split(',').filter(Boolean) || [],
        readableOn: getParam(searchParams, 'source')?.split(',').filter(Boolean) || [],
        languages: {
          original: getParam(searchParams, 'origLang') || undefined,
          translated: getParam(searchParams, 'transLang')?.split(',').filter(Boolean) || [],
        },
        chapterCount: {
          min: getParam(searchParams, 'chapters') ? parseInt(getParam(searchParams, 'chapters')!) : undefined,
          max: undefined,
        },
        releasePeriod: {
          from: getParam(searchParams, 'dateFrom') || undefined,
          to: getParam(searchParams, 'dateTo') || undefined,
        },
        sortBy: getParam(searchParams, 'sort') || 'newest',
        sortOrder: 'desc',
        cursor: getParam(searchParams, 'cursor'),
        limit: parseInt(searchParams.get(P.limit) || '24'),
        mode: searchParams.get(P.mode) || 'all',
      }

      const validated = FilterSchema.safeParse(rawFilters)
      if (!validated.success) {
        throw new ApiError("Invalid filters", 400, ErrorCodes.VALIDATION_ERROR)
      }

      const filters = validated.data
      const queryStr = filters.q ? sanitizeInput(filters.q, 200) : null
      
      const supabase = await createClient()
      const { data: { user } } = await supabase.auth.getUser()

      // Fetch user profile for subscription status
      const dbUser = user ? await prisma.user.findUnique({
        where: { id: user.id },
        select: { subscription_tier: true }
      }) : null
      const isPremium = dbUser?.subscription_tier === 'premium'

      // Update heat scoring early
      if (queryStr && queryStr.length > 0) {
        await updateQueryHeat(queryStr, user?.id)
      }

      const requestedLimit = Math.min(Math.max(1, filters.limit), 100)


    const rawSource = getParam(searchParams, 'source')
    const source = rawSource && VALID_SOURCES.has(rawSource.toLowerCase()) ? rawSource.toLowerCase() : null
    const requestId = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`

    const cacheFilters = { ...filters, source }

    if (queryStr && !filters.cursor) {
      const cached = await getCachedSearchResult(queryStr, cacheFilters)
      if (cached) {
        recordSearchEvent({
          normalized_query: queryStr.toLowerCase().trim(),
          intent_type: 'TEXT',
          local_hit: true,
          external_attempted: false,
          results_count: cached.results.length,
          resolution_time_ms: Date.now() - startTime,
          status: 'cache_hit'
        })
        
        return NextResponse.json({
          status: 'complete',
          results: cached.results,
          ...(cached.total !== undefined && { total: cached.total }),
          has_more: cached.has_more,
          next_cursor: cached.next_cursor,
          filters_applied: cacheFilters,
          cache_hit: true,
          cached_at: cached.cached_at,
        })
      }

      const pendingRequestId = await checkPendingSearch(queryStr, cacheFilters)
      if (pendingRequestId) {
        const pendingResult = await waitForPendingSearch(queryStr, cacheFilters, { maxPendingWaitMs: 3000 })
        if (pendingResult) {
          return NextResponse.json({
            status: 'complete',
            results: pendingResult.results,
            ...(pendingResult.total !== undefined && { total: pendingResult.total }),
            has_more: pendingResult.has_more,
            next_cursor: pendingResult.next_cursor,
            filters_applied: cacheFilters,
            cache_hit: true,
            dedup_wait: true,
          })
        }
      }

      await markSearchPending(queryStr, cacheFilters, requestId)
    }

    let multipleSourceIds: Set<string> | null = null
    if (source === 'multiple') {
      multipleSourceIds = await getSeriesIdsWithMultipleSources(supabaseAdminRead)
      
      if (multipleSourceIds.size === 0) {
        if (queryStr) await clearPendingSearch(queryStr, cacheFilters)
        return NextResponse.json({
          status: 'complete',
          results: [],
          total: 0,
          has_more: false,
          next_cursor: null,
          filters_applied: cacheFilters
        })
      }
    }

    const supabaseQuery = buildSeriesQuery(supabaseAdminRead, filters, source, multipleSourceIds)
    const { data: results, count, error } = await supabaseQuery

    if (error) {
      if (queryStr) await clearPendingSearch(queryStr, cacheFilters)
      throw error
    }

    let processedResults = results || []
    if (source && source !== 'all' && source !== 'multiple') {
      processedResults = stripSourcesFromResults(processedResults)
    }

    const hasMore = processedResults.length > requestedLimit
    const trimmedResults = hasMore ? processedResults.slice(0, requestedLimit) : processedResults

    const seriesIds = trimmedResults.map((r: any) => r.id)
    const bestCovers = await getBestCoversBatch(seriesIds)
    
    const formattedResults = trimmedResults.map((r: any) => {
      const bestCover = bestCovers.get(r.id)
      const fallbackCover = isValidCoverUrl(r.cover_url) ? r.cover_url : null
      return {
        ...r,
        cover_url: bestCover?.cover_url || fallbackCover,
        cover_source: bestCover?.source_name || null,
        source: 'local'
      }
    })

    let nextCursor = null
    if (hasMore && formattedResults.length > 0) {
      const lastItem = formattedResults[formattedResults.length - 1]
      nextCursor = createSearchCursor(lastItem, filters.sortBy)
    }

    if (queryStr && !filters.cursor && formattedResults.length > 0) {
      await setCachedSearchResult(queryStr, cacheFilters, {
        results: formattedResults,
        total: count ?? undefined,
        has_more: hasMore,
        next_cursor: nextCursor,
      }, { ttlSeconds: formattedResults.length >= 5 ? 3600 : 300 })
      
      await clearPendingSearch(queryStr, cacheFilters)
    }

    let status = 'complete'
    if (queryStr && !filters.cursor && formattedResults.length < 5) {
      try {
        const intent = detectSearchIntent(queryStr, trimmedResults || [])
        
        const hasGoodMatch = formattedResults.some((r: any) => {
          const title = (r.title || '').toLowerCase()
          const q = queryStr.toLowerCase()
          return title.includes(q) || q.includes(title)
        })

        if (intent !== 'NOISE' || !hasGoodMatch) {
          const { shouldProceed, existingJobId } = await checkExternalSearchDedup(queryStr)
          
          if (!shouldProceed && existingJobId) {
            status = 'resolving'
          } else {
            // Check heat gating before allowing external search
            const heat = await getQueryHeat(queryStr)
            const isForcedIntent = ['follow', 'track', 'bookmark'].includes(intentParam || '')
            
            // PREMIUM BYPASS: Premium users bypass heat check if quota available
            let premiumBypass = false
            if (isPremium && user) {
              const quotaUsed = await getPremiumQuota(user.id)
              if (quotaUsed < 50) {
                premiumBypass = true
                await incrementPremiumQuota(user.id)
                console.log(`[Premium Bypass] user=${user.id} query="${queryStr}" quota=${quotaUsed + 1}/50`)
              }
            }

            const isHot = heat.count >= 2 || heat.unique_users >= 2
            const externalAllowed = isHot || isForcedIntent || premiumBypass
            
            const reason = premiumBypass ? 'premium_bypass' : (isForcedIntent ? 'forced' : (heat.unique_users >= 2 ? 'multi_user' : (heat.count >= 2 ? 'count_threshold' : 'skipped')))

            console.log(`[Search Gating] query="${queryStr}" heat_count=${heat.count} unique_users=${heat.unique_users} external_allowed=${externalAllowed} reason=${reason}`)

            if (externalAllowed) {
              const queryHash = Buffer.from(queryStr.toLowerCase().trim()).toString('base64').slice(0, 32)
              const cooldownKey = `${REDIS_KEY_PREFIX}cooldown:search:${ip}:${queryHash}`
              
              const redisReady = await waitForRedis(1000)
              
              if (redisReady) {
                const isCoolingDown = await redis.get(cooldownKey)
                
                if (!isCoolingDown) {
                  const [workersOnline, queueHealthy] = await Promise.all([
                    areWorkersOnline(),
                    isQueueHealthy(checkSourceQueue, 5000)
                  ])
                  
                  // PREMIUM PRIORITY: Set priority based on subscription
                  const jobPriority = isPremium ? SEARCH_PRIORITY.CRITICAL : (intent === 'KEYWORD_EXPLORATION' ? SEARCH_PRIORITY.STANDARD + 5 : SEARCH_PRIORITY.STANDARD)

                  if (workersOnline && queueHealthy) {
                    // CONCURRENCY CHECK: Premium users capped at 2 active jobs
                    if (isPremium && user) {
                      const activeJobs = await incrementPremiumConcurrency(user.id)
                      if (activeJobs > 2) {
                        console.warn(`[Search Limit] Premium user=${user.id} exceeded concurrency cap (${activeJobs}). Deferring.`)
                        await deferSearchQuery(queryStr, 'queue_unhealthy', true)
                        return NextResponse.json({
                          status: 'resolving',
                          results: formattedResults,
                          has_more: hasMore,
                          next_cursor: nextCursor,
                          filters_applied: cacheFilters
                        })
                      }
                    }

                    const jobId = `search_${queryHash}`
                    await checkSourceQueue.add('check-source', {
                      query: queryStr,
                      intent,
                      trigger: 'user_search',
                      userId: user?.id, // Pass userId for concurrency tracking in worker
                      isPremium,
                    }, {
                      jobId,
                      priority: jobPriority,
                      removeOnComplete: true,
                    })
                    await redis.set(cooldownKey, "1", "EX", 30)
                    await markExternalSearchPending(queryStr, jobId, 60)
                    status = 'resolving'
                  } else {
                    // Defer search if system is under load or workers are offline
                    const skipReason = !workersOnline ? 'workers_offline' : 'queue_unhealthy'
                    await deferSearchQuery(queryStr, skipReason, isPremium)
                  }
                }
              }
            } else {
              // Defer search if heat is too low
              await deferSearchQuery(queryStr, 'low_heat', isPremium)
            }
          }

        }
      } catch (e: any) {
        console.error("[Search] Redis/Queue resilience fallback:", e.message)
      } finally {
        if (queryStr) {
          try {
            await clearPendingSearch(queryStr, cacheFilters)
          } catch (cleanupError) {
            console.error("[Search] Failed to clear pending search:", cleanupError)
          }
        }
      }
    }

    recordSearchEvent({
      normalized_query: queryStr?.toLowerCase().trim() || 'none',
      intent_type: queryStr ? 'TEXT' : 'FILTER',
      local_hit: formattedResults.length > 0,
      external_attempted: status === 'resolving',
      results_count: formattedResults.length,
      resolution_time_ms: Date.now() - startTime,
      status
    })

    return NextResponse.json({
      status,
      results: formattedResults,
      ...(count !== null && !filters.cursor && { total: count }),
      has_more: hasMore,
      next_cursor: nextCursor,
      filters_applied: cacheFilters
    })

  } catch (error: any) {
    return handleApiError(error)
  }
}
