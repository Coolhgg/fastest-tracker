
'use server'

import { revalidatePath } from 'next/cache'
import { createClient } from '@/lib/supabase/server'
import { z } from 'zod'

// FIX H2: Added Zod validation schemas
const UUIDSchema = z.string().uuid('Invalid UUID format')
const StatusSchema = z.enum(['reading', 'completed', 'planning', 'dropped', 'paused'])
const ChapterSchema = z.number().min(0).max(100000).finite()
const RatingSchema = z.number().int().min(1).max(10)

export async function addToLibrary(seriesId: string, status: string = 'reading') {
  // Validate inputs
  const seriesIdResult = UUIDSchema.safeParse(seriesId)
  if (!seriesIdResult.success) {
    return { error: 'Invalid series ID format' }
  }
  
  const statusResult = StatusSchema.safeParse(status)
  if (!statusResult.success) {
    return { error: 'Invalid status. Must be one of: reading, completed, planning, dropped, paused' }
  }

  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  
  if (!user) {
    return { error: 'Not authenticated' }
  }

  const { data, error } = await supabase
    .from('library_entries')
    .insert({
      user_id: user.id,
      series_id: seriesIdResult.data,
      status: statusResult.data,
      last_read_chapter: 0,
      notify_new_chapters: true,
      sync_priority: 'WARM',
    })
    .select()
    .single()

  if (error) {
    if (error.code === '23505') {
      return { error: 'Series already in library' }
    }
    return { error: error.message }
  }

  // Log activity
  await supabase.from('activities').insert({
    user_id: user.id,
    type: 'series_added',
    series_id: seriesIdResult.data,
    metadata: { status: statusResult.data }
  })

  revalidatePath('/library')
  revalidatePath('/discover')
  revalidatePath('/feed')
  return { data }
}

export async function removeFromLibrary(entryId: string) {
  // Validate input
  const entryIdResult = UUIDSchema.safeParse(entryId)
  if (!entryIdResult.success) {
    return { error: 'Invalid entry ID format' }
  }

  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  
  if (!user) {
    return { error: 'Not authenticated' }
  }

  const { error } = await supabase
    .from('library_entries')
    .delete()
    .eq('id', entryIdResult.data)
    .eq('user_id', user.id)

  if (error) {
    return { error: error.message }
  }

  revalidatePath('/library')
  revalidatePath('/feed')
  return { success: true }
}

export async function updateProgress(entryId: string, chapter: number, seriesId: string, sourceId?: string) {
  // Validate inputs
  const entryIdResult = UUIDSchema.safeParse(entryId)
  if (!entryIdResult.success) {
    return { error: 'Invalid entry ID format' }
  }
  
  const seriesIdResult = UUIDSchema.safeParse(seriesId)
  if (!seriesIdResult.success) {
    return { error: 'Invalid series ID format' }
  }
  
  const chapterResult = ChapterSchema.safeParse(chapter)
  if (!chapterResult.success) {
    return { error: 'Invalid chapter number. Must be a number between 0 and 100000' }
  }

  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  
  if (!user) {
    return { error: 'Not authenticated' }
  }

  const { data, error } = await supabase
    .from('library_entries')
    .update({
      last_read_chapter: chapterResult.data,
      last_read_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    })
    .eq('id', entryIdResult.data)
    .eq('user_id', user.id)
    .select()
    .single()

  if (error) {
    return { error: error.message }
  }

  // Update user's last_read_at
  await supabase
    .from('users')
    .update({
      last_read_at: new Date().toISOString(),
    })
    .eq('id', user.id)

  // Award XP for reading
  await supabase.rpc('increment_xp', { user_id: user.id, amount: 10 })

  // Log activity
  await supabase.from('activities').insert({
    user_id: user.id,
    type: 'chapter_read',
    series_id: seriesIdResult.data,
    metadata: { 
      chapter_number: chapterResult.data,
      source_id: sourceId 
    }
  })

  // Record Chapter Read V2 (Telemetry)
  const { data: logicalChapter } = await supabase
    .from('logical_chapters')
    .select('id')
    .eq('series_id', seriesIdResult.data)
    .eq('chapter_number', chapterResult.data)
    .single()

  if (logicalChapter) {
    await supabase.from('user_chapter_reads_v2').upsert({
      user_id: user.id,
      chapter_id: logicalChapter.id,
      source_used_id: sourceId,
      read_at: new Date().toISOString(),
    }, {
      onConflict: 'user_id,chapter_id'
    })
  }

  revalidatePath('/library')
  revalidatePath('/feed')
  revalidatePath(`/series/${seriesIdResult.data}`)
  return { data, xp_gained: 10 }
}

export async function updateStatus(entryId: string, status: string, seriesId: string) {
  // Validate inputs
  const entryIdResult = UUIDSchema.safeParse(entryId)
  if (!entryIdResult.success) {
    return { error: 'Invalid entry ID format' }
  }
  
  const seriesIdResult = UUIDSchema.safeParse(seriesId)
  if (!seriesIdResult.success) {
    return { error: 'Invalid series ID format' }
  }
  
  const statusResult = StatusSchema.safeParse(status)
  if (!statusResult.success) {
    return { error: 'Invalid status. Must be one of: reading, completed, planning, dropped, paused' }
  }

  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  
  if (!user) {
    return { error: 'Not authenticated' }
  }

  const { data, error } = await supabase
    .from('library_entries')
    .update({
      status: statusResult.data,
      updated_at: new Date().toISOString(),
    })
    .eq('id', entryIdResult.data)
    .eq('user_id', user.id)
    .select()
    .single()

  if (error) {
    return { error: error.message }
  }

  // If completed, award bonus XP
  if (statusResult.data === 'completed') {
    await supabase.rpc('increment_xp', { user_id: user.id, amount: 100 })
    
    // Log activity
    await supabase.from('activities').insert({
      user_id: user.id,
      type: 'series_completed',
      series_id: seriesIdResult.data
    })
  }

  revalidatePath('/library')
  revalidatePath('/feed')
  revalidatePath(`/series/${seriesIdResult.data}`)
  return { data }
}

export async function updateRating(entryId: string, rating: number) {
  // Validate inputs
  const entryIdResult = UUIDSchema.safeParse(entryId)
  if (!entryIdResult.success) {
    return { error: 'Invalid entry ID format' }
  }
  
  const ratingResult = RatingSchema.safeParse(rating)
  if (!ratingResult.success) {
    return { error: 'Invalid rating. Must be an integer between 1 and 10' }
  }

  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  
  if (!user) {
    return { error: 'Not authenticated' }
  }

  const { data, error } = await supabase
    .from('library_entries')
    .update({
      user_rating: ratingResult.data,
      updated_at: new Date().toISOString(),
    })
    .eq('id', entryIdResult.data)
    .eq('user_id', user.id)
    .select()
    .single()

  if (error) {
    return { error: error.message }
  }

  revalidatePath('/library')
  return { data }
}
