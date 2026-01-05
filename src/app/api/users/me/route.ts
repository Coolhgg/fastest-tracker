import { NextRequest, NextResponse } from "next/server"
import { createClient } from "@/lib/supabase/server"
import { supabaseAdmin } from "@/lib/supabase/admin"
import { prisma, withRetry, isTransientError } from "@/lib/prisma"
import { checkRateLimit, handleApiError, ApiError, ErrorCodes, sanitizeInput, sanitizeText, validateOrigin, USERNAME_REGEX, getClientIp } from "@/lib/api-utils"
import { z } from "zod"

const UpdateProfileSchema = z.object({
  username: z.string().min(3).max(20).regex(USERNAME_REGEX, "Username can only contain letters, numbers, underscores, and hyphens").optional(),
  bio: z.string().max(500).optional(),
  avatar_url: z.string().url().optional().or(z.literal("")),
  notification_settings: z.object({
    email_new_chapters: z.boolean().optional(),
    email_follows: z.boolean().optional(),
    email_achievements: z.boolean().optional(),
    push_enabled: z.boolean().optional(),
  }).optional(),
  privacy_settings: z.object({
    library_public: z.boolean().optional(),
    activity_public: z.boolean().optional(),
    followers_public: z.boolean().optional(),
    following_public: z.boolean().optional(),
    profile_searchable: z.boolean().optional(),
  }).optional(),
  safe_browsing_mode: z.enum(['sfw', 'sfw_plus', 'nsfw']).optional(),
    safe_browsing_indicator: z.enum(['toggle', 'icon', 'hidden']).optional(),
    default_source: z.string().max(50).optional().nullable(),
    notification_digest: z.enum(['immediate', 'short', 'hourly', 'daily']).optional(),
  })


export async function GET(request: NextRequest) {
  try {
    // Rate limit: 60 requests per minute per IP
    const ip = getClientIp(request)
    if (!await checkRateLimit(`users-me:${ip}`, 60, 60000)) {
      throw new ApiError('Too many requests. Please wait a moment.', 429, ErrorCodes.RATE_LIMITED)
    }

    const supabase = await createClient()
    const { data: { user }, error: authError } = await supabase.auth.getUser()

    if (authError) {
      throw new ApiError("Authentication failed", 401, ErrorCodes.UNAUTHORIZED)
    }

    if (!user) {
      throw new ApiError("Unauthorized", 401, ErrorCodes.UNAUTHORIZED)
    }

    // Generate fallback username from Supabase data
    const fallbackUsername = user.user_metadata?.username || 
                            user.email?.split('@')[0]?.replace(/[^a-z0-9_]/gi, '').toLowerCase() || 
                            `user_${user.id.slice(0, 8)}`

    // Create fallback response for when DB is unavailable
    const createFallbackResponse = (warning: string) => ({
      id: user.id,
      email: user.email,
      username: fallbackUsername,
      avatar_url: user.user_metadata?.avatar_url || null,
      bio: null,
      xp: 0,
      level: 1,
      streak_days: 0,
      longest_streak: 0,
      chapters_read: 0,
      library_count: 0,
      followers_count: 0,
      following_count: 0,
      safe_browsing_mode: 'sfw',
      safe_browsing_indicator: 'toggle',
      default_source: null,
      _synced: false,
      _warning: warning
    })

    // Try to get user from database with retry logic
    let dbUser = null
    try {
      dbUser = await withRetry(
          () => prisma.user.findUnique({
            where: { id: user.id },
            select: {
              id: true,
              email: true,
              username: true,
              avatar_url: true,
              bio: true,
              xp: true,
              level: true,
              streak_days: true,
              longest_streak: true,
              chapters_read: true,
              created_at: true,
              updated_at: true,
              privacy_settings: true,
              notification_settings: true,
              safe_browsing_mode: true,
                safe_browsing_indicator: true,
                default_source: true,
                notification_digest: true,
                _count: {

                select: {
                  library_entries: true,
                  followers: true,
                  following: true,
                },
              },
            },
          }),
          3,
          200
        )
    } catch (dbError: any) {
      console.warn("Database connection error in /api/users/me:", dbError.message?.slice(0, 100))
      
      // If it's a transient database error, return a degraded response with Supabase data
      if (isTransientError(dbError)) {
        return NextResponse.json(createFallbackResponse("Could not connect to database. Some data may be unavailable."))
      }
      throw dbError
    }

    // AUTO-SYNC: If user exists in Supabase but not in Prisma, create them
    if (!dbUser) {
      console.log("User exists in Supabase but not Prisma, auto-creating:", user.id)
      
      // Check for username collisions and make unique if needed
      let username = fallbackUsername.slice(0, 20) // Ensure max length
      let suffix = 1
      
      try {
        while (await withRetry(() => prisma.user.findFirst({ 
          where: { username: { equals: username, mode: 'insensitive' } } 
        }))) {
          username = `${fallbackUsername.slice(0, 16)}${suffix}`
          suffix++
          if (suffix > 999) {
            username = `user_${Date.now().toString(36)}`
            break
          }
        }
        
          dbUser = await withRetry(
            () => prisma.user.create({
              data: {
                id: user.id,
                email: user.email!,
                username,
                password_hash: '', // OAuth users don't have a password
                xp: 0,
                level: 1,
                streak_days: 0,
                longest_streak: 0,
                chapters_read: 0,
                subscription_tier: 'free',
                notification_settings: {
                  email_new_chapters: true,
                  email_follows: true,
                  email_achievements: true,
                  push_enabled: false,
                },
                privacy_settings: { library_public: true, activity_public: true },
                safe_browsing_mode: 'sfw',
                safe_browsing_indicator: 'toggle',
                avatar_url: user.user_metadata?.avatar_url || null,
              },
              select: {
                id: true,
                email: true,
                username: true,
                avatar_url: true,
                bio: true,
                xp: true,
                level: true,
                streak_days: true,
                longest_streak: true,
                chapters_read: true,
                created_at: true,
                updated_at: true,
                privacy_settings: true,
                notification_settings: true,
                safe_browsing_mode: true,
                safe_browsing_indicator: true,
                default_source: true,
                _count: {
                  select: {
                    library_entries: true,
                    followers: true,
                    following: true,
                  },
                },
              },
            }),
            2,
            300
          )
      } catch (createError: any) {
        // Handle race condition where user was created between check and create
        if (createError.code === 'P2002') {
          dbUser = await withRetry(
            () => prisma.user.findUnique({
              where: { id: user.id },
              select: {
                id: true,
                email: true,
                username: true,
                avatar_url: true,
                bio: true,
                xp: true,
                level: true,
                streak_days: true,
                longest_streak: true,
                chapters_read: true,
                created_at: true,
                updated_at: true,
                privacy_settings: true,
                notification_settings: true,
                safe_browsing_mode: true,
                safe_browsing_indicator: true,
                default_source: true,
                _count: {
                  select: {
                    library_entries: true,
                    followers: true,
                    following: true,
                  },
                },
              },
            }),
            2,
            200
          )
        } else if (isTransientError(createError)) {
          // Database is unavailable, return Supabase data
          return NextResponse.json(createFallbackResponse("Account created but database sync pending. Some features may be limited."))
        } else {
          throw createError
        }
      }
    }

    if (!dbUser) {
      // Fallback: Return Supabase data if no DB user
      return NextResponse.json(createFallbackResponse("User profile not found in database."))
    }

    return NextResponse.json({
      id: dbUser.id,
      email: dbUser.email,
      username: dbUser.username,
      avatar_url: dbUser.avatar_url,
      bio: dbUser.bio,
      xp: dbUser.xp,
      level: dbUser.level,
      streak_days: dbUser.streak_days,
      longest_streak: dbUser.longest_streak,
      chapters_read: dbUser.chapters_read,
      created_at: dbUser.created_at,
      updated_at: dbUser.updated_at,
      privacy_settings: dbUser.privacy_settings,
      notification_settings: dbUser.notification_settings,
      safe_browsing_mode: dbUser.safe_browsing_mode,
      safe_browsing_indicator: dbUser.safe_browsing_indicator,
      default_source: dbUser.default_source,
      notification_digest: dbUser.notification_digest,
      library_count: dbUser._count?.library_entries || 0,
      followers_count: dbUser._count?.followers || 0,
      following_count: dbUser._count?.following || 0,
    })
  } catch (error: any) {
    return handleApiError(error)
  }
}

export async function PATCH(request: NextRequest) {
  try {
    // CSRF Protection
    validateOrigin(request)

    // Rate limit: 20 profile updates per minute per IP
    const ip = getClientIp(request)
    if (!await checkRateLimit(`users-me-update:${ip}`, 20, 60000)) {
      throw new ApiError('Too many requests. Please wait a moment.', 429, ErrorCodes.RATE_LIMITED)
    }

    const supabase = await createClient()
    const { data: { user } } = await supabase.auth.getUser()

    if (!user) {
      throw new ApiError("Unauthorized", 401, ErrorCodes.UNAUTHORIZED)
    }

    let body
    try {
      body = await request.json()
    } catch {
      throw new ApiError("Invalid JSON body", 400, ErrorCodes.BAD_REQUEST)
    }
    
    const validatedBody = UpdateProfileSchema.safeParse(body)
    if (!validatedBody.success) {
      throw new ApiError(validatedBody.error.errors[0].message, 400, ErrorCodes.VALIDATION_ERROR)
    }

    const { username, bio, avatar_url, notification_settings, privacy_settings, safe_browsing_mode, safe_browsing_indicator, default_source, notification_digest } = validatedBody.data

    const updateData: Record<string, unknown> = {}
    if (username !== undefined) updateData.username = sanitizeInput(username.toLowerCase(), 20)
    if (bio !== undefined) updateData.bio = sanitizeText(bio, 500)
    if (avatar_url !== undefined) updateData.avatar_url = avatar_url
    if (notification_settings !== undefined) updateData.notification_settings = notification_settings
    if (privacy_settings !== undefined) updateData.privacy_settings = privacy_settings
    if (safe_browsing_mode !== undefined) updateData.safe_browsing_mode = safe_browsing_mode
    if (safe_browsing_indicator !== undefined) updateData.safe_browsing_indicator = safe_browsing_indicator
    if (default_source !== undefined) updateData.default_source = default_source
    if (notification_digest !== undefined) updateData.notification_digest = notification_digest

    // FIX H3: Use transaction with unique constraint as primary enforcement
    const updatedUser = await withRetry(
      async () => {
        // If username is being changed, use a transaction to handle race conditions
        if (username !== undefined) {
          return prisma.$transaction(async (tx) => {
            // Check if username is taken (secondary check - DB constraint is primary)
            const existing = await tx.user.findFirst({
              where: { 
                username: { equals: username, mode: 'insensitive' },
                id: { not: user.id },
              },
            })
            
            if (existing) {
              throw new ApiError("Username is already taken", 409, ErrorCodes.CONFLICT)
            }
            
            return tx.user.update({
              where: { id: user.id },
              data: updateData,
              select: {
                id: true,
                email: true,
                username: true,
                avatar_url: true,
                bio: true,
                xp: true,
                level: true,
                notification_settings: true,
                privacy_settings: true,
                safe_browsing_mode: true,
                  safe_browsing_indicator: true,
                  default_source: true,
                  notification_digest: true,
                },
              })
            })
          }
          
          // No username change, simple update
          return prisma.user.update({
            where: { id: user.id },
            data: updateData,
            select: {
              id: true,
              email: true,
              username: true,
              avatar_url: true,
              bio: true,
              xp: true,
              level: true,
              notification_settings: true,
              privacy_settings: true,
              safe_browsing_mode: true,
              safe_browsing_indicator: true,
              default_source: true,
              notification_digest: true,
            },
          })

      },
      2,
      200
    )

    return NextResponse.json(updatedUser)
  } catch (error: any) {
    // Handle unique constraint violation (race condition fallback)
    if (error.code === 'P2002' && error.meta?.target?.includes('username')) {
      return handleApiError(new ApiError("Username is already taken", 409, ErrorCodes.CONFLICT))
    }
    return handleApiError(error)
  }
}

export async function DELETE(request: NextRequest) {
  try {
    // CSRF Protection
    validateOrigin(request)

    // Rate limit: 5 account deletions per hour per IP
    const ip = getClientIp(request)
    if (!await checkRateLimit(`users-me-delete:${ip}`, 5, 3600000)) {
      throw new ApiError('Too many requests. Please try again later.', 429, ErrorCodes.RATE_LIMITED)
    }

    const supabase = await createClient()
    const { data: { user } } = await supabase.auth.getUser()

    if (!user) {
      throw new ApiError("Unauthorized", 401, ErrorCodes.UNAUTHORIZED)
    }

    // Delete user from Supabase Auth first
    // This ensures they cannot log in anymore even if DB deletion fails partially
    // Note: This requires service role key which supabaseAdmin has
    const { error: deleteError } = await supabaseAdmin.auth.admin.deleteUser(user.id)
    
    if (deleteError) {
      // If the error is that the user doesn't exist, we can proceed with DB deletion
      // Otherwise, we should fail to be safe
      const isNotFoundError = deleteError.message?.toLowerCase().includes('not found') || (deleteError as any).status === 404
      if (!isNotFoundError) {
        console.error("[Auth] Failed to delete user from Supabase:", deleteError)
        throw new ApiError("Failed to delete account from authentication service", 500, ErrorCodes.INTERNAL_ERROR)
      }
    }

    // Delete user from database (cascading delete should handle related entries)
    await withRetry(
      () => prisma.user.delete({
        where: { id: user.id }
      }),
      2,
      500
    )

    return NextResponse.json({ success: true, message: "Account deleted successfully" })
  } catch (error: any) {
    return handleApiError(error)
  }
}
