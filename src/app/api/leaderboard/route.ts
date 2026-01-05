import { NextRequest, NextResponse } from "next/server"
import { prisma, withRetry, isTransientError } from "@/lib/prisma"
import { checkRateLimit, getClientIp, handleApiError, ApiError, ErrorCodes } from "@/lib/api-utils"

const VALID_CATEGORIES = ['xp', 'streak', 'chapters'] as const
const VALID_PERIODS = ['week', 'month', 'all-time'] as const

export async function GET(request: NextRequest) {
  try {
    // Rate limit: 30 requests per minute per IP
    const ip = getClientIp(request)
    if (!await checkRateLimit(`leaderboard:${ip}`, 30, 60000)) {
      throw new ApiError('Too many requests. Please wait a moment.', 429, ErrorCodes.RATE_LIMITED)
    }

    const { searchParams } = new URL(request.url)
    const period = searchParams.get("period") || "all-time"
    const category = searchParams.get("category") || "xp"
    const limit = Math.min(Math.max(1, parseInt(searchParams.get("limit") || "50")), 100)

    // Validate category
    if (!VALID_CATEGORIES.includes(category as any)) {
      throw new ApiError(`Invalid category. Must be one of: ${VALID_CATEGORIES.join(', ')}`, 400, ErrorCodes.VALIDATION_ERROR)
    }

    // Validate period
    if (!VALID_PERIODS.includes(period as any)) {
      throw new ApiError(`Invalid period. Must be one of: ${VALID_PERIODS.join(', ')}`, 400, ErrorCodes.VALIDATION_ERROR)
    }

    let orderBy: any = { xp: "desc" }
    const selectFields: any = {
      id: true,
      username: true,
      avatar_url: true,
      xp: true,
      level: true,
      streak_days: true,
      chapters_read: true,
    }
    
    if (category === "streak") {
      orderBy = { streak_days: "desc" }
    } else if (category === "chapters") {
      orderBy = { chapters_read: "desc" }
    }

    const where: any = {}
    
    // Filter out users with no activity in the category
    if (category === "streak") {
      where.streak_days = { gt: 0 }
    } else if (category === "chapters") {
      where.chapters_read = { gt: 0 }
    } else {
      where.xp = { gt: 0 }
    }
    
    const users = await withRetry(
      () => prisma.user.findMany({
        select: selectFields,
        orderBy,
        take: limit,
        where,
      }),
      3,
      200
    )

    // Add rank to each user
    const rankedUsers = users.map((user, index) => ({
      rank: index + 1,
      ...user,
    }))

    return NextResponse.json({ 
      users: rankedUsers,
      category,
      period,
      total: rankedUsers.length,
    })
  } catch (error: any) {
    // Check for transient database errors
    if (isTransientError(error)) {
      return NextResponse.json(
        { 
          error: 'Database temporarily unavailable',
          code: ErrorCodes.INTERNAL_ERROR,
          users: [],
          category: 'xp',
          period: 'all-time',
          total: 0
        },
        { status: 503 }
      )
    }
    
    return handleApiError(error)
  }
}
