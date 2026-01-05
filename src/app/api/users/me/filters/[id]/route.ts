import { createClient } from "@/lib/supabase/server"
import { NextRequest, NextResponse } from "next/server"
import { checkRateLimit, validateOrigin, validateUUID, sanitizeInput, handleApiError, ApiError } from "@/lib/api-utils"

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // CSRF Protection
    validateOrigin(request)

    // Rate limit: 20 updates per minute per IP
    const ip = getClientIp(request);
    if (!await checkRateLimit(`filters-update:${ip}`, 20, 60000)) {
      throw new ApiError("Too many requests. Please wait a moment.", 429)
    }

    const supabase = await createClient()
    const { data: { user } } = await supabase.auth.getUser()

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    const { id } = await params
    
    // Validate UUID format
    validateUUID(id, 'filter id')

    let body
    try {
      body = await request.json()
    } catch {
      throw new ApiError("Invalid JSON body", 400)
    }

    const { name, is_default } = body

    // Build update object with only provided fields
    const updateData: Record<string, any> = {
      updated_at: new Date().toISOString()
    }

    if (name !== undefined) {
      if (typeof name !== 'string') {
        throw new ApiError("Name must be a string", 400)
      }
      const sanitizedName = sanitizeInput(name, 100).trim()
      if (sanitizedName.length < 1 || sanitizedName.length > 100) {
        throw new ApiError("Filter name must be between 1 and 100 characters", 400)
      }
      updateData.name = sanitizedName
    }

    if (is_default !== undefined) {
      updateData.is_default = !!is_default

      // If setting as default, unset previous default
      if (is_default) {
        await supabase
          .from('saved_filters')
          .update({ is_default: false })
          .eq('user_id', user.id)
          .neq('id', id)
      }
    }

    const { data, error } = await supabase
      .from('saved_filters')
      .update(updateData)
      .eq('id', id)
      .eq('user_id', user.id) // Ensure user owns this filter
      .select()
      .single()

    if (error) {
      if (error.code === 'PGRST116') {
        throw new ApiError("Filter not found", 404)
      }
      console.error('[Filters PATCH] Database error:', error)
      throw new ApiError("Failed to update filter", 500)
    }

    if (!data) {
      throw new ApiError("Filter not found", 404)
    }

    return NextResponse.json(data)
  } catch (error) {
    return handleApiError(error)
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // CSRF Protection
    validateOrigin(request)

    // Rate limit: 20 deletes per minute per IP
    const ip = request.headers.get("x-forwarded-for") || request.headers.get("x-real-ip") || "unknown"
    if (!await checkRateLimit(`filters-delete:${ip}`, 20, 60000)) {
      throw new ApiError("Too many requests. Please wait a moment.", 429)
    }

    const supabase = await createClient()
    const { data: { user } } = await supabase.auth.getUser()

    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    const { id } = await params
    
    // Validate UUID format
    validateUUID(id, 'filter id')

    // Check filter exists and belongs to user before deleting
    const { data: existing } = await supabase
      .from('saved_filters')
      .select('id')
      .eq('id', id)
      .eq('user_id', user.id)
      .single()

    if (!existing) {
      throw new ApiError("Filter not found", 404)
    }

    const { error } = await supabase
      .from('saved_filters')
      .delete()
      .eq('id', id)
      .eq('user_id', user.id)

    if (error) {
      console.error('[Filters DELETE] Database error:', error)
      throw new ApiError("Failed to delete filter", 500)
    }

    return new NextResponse(null, { status: 204 })
  } catch (error) {
    return handleApiError(error)
  }
}
