import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { followUser, unfollowUser, checkFollowStatus } from "@/lib/social-utils";
import { prisma } from "@/lib/prisma";
import { checkRateLimit, validateUsername, handleApiError, ApiError, ErrorCodes, validateOrigin, getClientIp } from "@/lib/api-utils";

export async function GET(
  request: Request,
  { params }: { params: Promise<{ username: string }> }
) {
  try {
    // Rate limit: 60 requests per minute per IP
    const ip = getClientIp(request);
    if (!await checkRateLimit(`follow-status:${ip}`, 60, 60000)) {
      throw new ApiError("Too many requests. Please wait a moment.", 429, ErrorCodes.RATE_LIMITED);
    }

    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      throw new ApiError("Unauthorized", 401, ErrorCodes.UNAUTHORIZED);
    }

    const { username } = await params;

    // Validate username format
    if (!validateUsername(username)) {
      throw new ApiError("Invalid username format", 400, ErrorCodes.VALIDATION_ERROR);
    }

    // Get target user ID with case-insensitivity
    const target = await prisma.user.findFirst({
      where: { 
        username: { 
          equals: username, 
          mode: 'insensitive' 
        } 
      },
      select: { id: true },
    });

    if (!target) {
      throw new ApiError("User not found", 404, ErrorCodes.NOT_FOUND);
    }

    const isFollowing = await checkFollowStatus(user.id, target.id);

    return NextResponse.json({ isFollowing });
  } catch (error: any) {
    return handleApiError(error);
  }
}

export async function POST(
  request: Request,
  { params }: { params: Promise<{ username: string }> }
) {
  try {
    // CSRF Protection
    validateOrigin(request);

    // Rate limit: 30 follow actions per minute per IP
    const ip = getClientIp(request);
    if (!await checkRateLimit(`follow-action:${ip}`, 30, 60000)) {
      throw new ApiError("Too many requests. Please wait a moment.", 429, ErrorCodes.RATE_LIMITED);
    }

    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      throw new ApiError("Unauthorized", 401, ErrorCodes.UNAUTHORIZED);
    }

    const { username } = await params;

    // Validate username format
    if (!validateUsername(username)) {
      throw new ApiError("Invalid username format", 400, ErrorCodes.VALIDATION_ERROR);
    }

    const follow = await followUser(user.id, username);

    return NextResponse.json(follow, { status: 201 });
  } catch (error: any) {
    return handleApiError(error);
  }
}

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ username: string }> }
) {
  try {
    // CSRF Protection
    validateOrigin(request);

    // Rate limit: 30 unfollow actions per minute per IP
    // FIX: Use getClientIp instead of raw header access
    const ip = getClientIp(request);
    if (!await checkRateLimit(`follow-action:${ip}`, 30, 60000)) {
      throw new ApiError("Too many requests. Please wait a moment.", 429, ErrorCodes.RATE_LIMITED);
    }

    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      throw new ApiError("Unauthorized", 401, ErrorCodes.UNAUTHORIZED);
    }

    const { username } = await params;

    // Validate username format
    if (!validateUsername(username)) {
      throw new ApiError("Invalid username format", 400, ErrorCodes.VALIDATION_ERROR);
    }

    await unfollowUser(user.id, username);

    return NextResponse.json({ success: true });
  } catch (error: any) {
    return handleApiError(error);
  }
}
