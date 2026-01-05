'use server'

import { revalidatePath } from 'next/cache'
import { redirect } from 'next/navigation'
import { createClient } from '@/lib/supabase/server'
import { prisma } from '@/lib/prisma'
import { hashPassword, comparePasswords } from '@/lib/auth-utils'

/**
 * Robust login handler that ensures Prisma and Supabase are in sync
 */
export async function login(formData: FormData) {
  const email = formData.get('email') as string
  const password = formData.get('password') as string

  if (!email || !password) {
    redirect('/login?error=' + encodeURIComponent('Email and password are required'))
  }

  let success = false
  let errorMessage = ''
  const targetUrl = '/library'

  try {
    console.log('Login attempt for:', email)
    
    // 1. Verify user exists in our database
    const user = await prisma.user.findUnique({
      where: { email }
    })

    const supabase = await createClient()

    if (!user) {
      console.log('User not found in Prisma, checking Supabase recovery for:', email)
      // Recovery: Check if they exist in Supabase but not in Prisma
      const { data: signInData, error: signInError } = await supabase.auth.signInWithPassword({ email, password })
      
      if (signInError) {
        console.error('Supabase recovery login failed:', signInError.message)
        errorMessage = signInError.message === 'Invalid login credentials' 
          ? 'Invalid email or password' 
          : signInError.message
      } else if (signInData.user) {
        console.log('Supabase recovery login success, syncing to Prisma:', signInData.user.id)
        // Sync them to Prisma if missing
        const password_hash = await hashPassword(password)
        await prisma.user.upsert({
          where: { id: signInData.user.id },
          update: { email },
          create: {
            id: signInData.user.id,
            email,
            username: signInData.user.user_metadata?.username || email.split('@')[0],
            password_hash,
            xp: 0,
            level: 1,
            subscription_tier: 'free',
          }
        })
        success = true
      }
    } else {
      // Regular flow: compare passwords against our DB
      const isPasswordValid = await comparePasswords(password, user.password_hash)
      
      if (!isPasswordValid) {
        // Fallback: check Supabase just in case passwords got out of sync
        const { data: signInData, error: fallbackError } = await supabase.auth.signInWithPassword({ email, password })
        if (!fallbackError && signInData.user) {
          console.log('Password mismatch in Prisma but success in Supabase, updating Prisma hash')
          const password_hash = await hashPassword(password)
          await prisma.user.update({
            where: { id: user.id },
            data: { password_hash }
          })
          success = true
        } else {
          errorMessage = 'Invalid email or password'
        }
      } else {
        // 2. Sign into Supabase Auth for session management
        const { error } = await supabase.auth.signInWithPassword({ email, password })

        if (error) {
          console.error('Supabase session creation failed:', error.message)
          errorMessage = error.message
          // Specific handling for common error
          if (error.message.includes('Email not confirmed')) {
            errorMessage = 'Please confirm your email before logging in.'
          }
        } else {
          success = true
        }
      }
    }
  } catch (err: any) {
    // IMPORTANT: Always rethrow redirect errors in Next.js
    if (err.digest?.includes('NEXT_REDIRECT') || err.message === 'NEXT_REDIRECT') {
      throw err
    }
    
    console.error('CRITICAL Login error:', err)
    errorMessage = 'An unexpected server error occurred. Please try again later.'
  }

  // Handle results outside of try/catch to avoid catching the redirect error
  if (success) {
    revalidatePath('/', 'layout')
    redirect(targetUrl)
  } else {
    redirect('/login?error=' + encodeURIComponent(errorMessage || 'Login failed'))
  }
}

/**
 * Robust signup handler with duplicate handling
 */
export async function signup(formData: FormData) {
  const email = formData.get('email') as string
  const password = formData.get('password') as string
  const username = formData.get('username') as string

  if (!email || !password || !username) {
    redirect('/register?error=' + encodeURIComponent('All fields are required'))
  }

  let success = false
  let errorMessage = ''
  let needsConfirmation = false

  try {
    console.log('Signup attempt for:', email, username)
    
    // 1. Check if user already exists in Prisma
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [
          { email },
          { username }
        ]
      }
    })

    if (existingUser) {
      errorMessage = 'User already exists with this email or username'
    } else {
      // 2. Create user in Supabase Auth
      const supabase = await createClient()
      const { data: authData, error: authError } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: { username }
        }
      })

      if (authError) {
        console.error('Supabase signup failed:', authError.message)
        errorMessage = authError.message
      } else if (!authData.user) {
        errorMessage = 'Failed to create account'
      } else {
        console.log('Supabase signup success, user ID:', authData.user.id)
        
        // Check if user is already confirmed (happens if email confirmation is off)
        const isConfirmed = !!authData.user.email_confirmed_at
        
        // 3. Create user profile in Prisma with hashed password
        const password_hash = await hashPassword(password)
        
        await prisma.user.upsert({
          where: { id: authData.user.id },
          update: {
            email,
            username,
            password_hash
          },
          create: {
            id: authData.user.id,
            email,
            username,
            password_hash,
            xp: 0,
            level: 1,
            streak_days: 0,
            subscription_tier: 'free',
            notification_settings: { email: true, push: false },
            privacy_settings: { library_public: true, activity_public: true },
          }
        })
        
        if (isConfirmed) {
          success = true
        } else {
          needsConfirmation = true
        }
      }
    }
  } catch (err: any) {
    if (err.digest?.includes('NEXT_REDIRECT') || err.message === 'NEXT_REDIRECT') {
      throw err
    }
    
    console.error('CRITICAL Registration error:', err)
    errorMessage = 'An unexpected error occurred during registration.'
  }

  if (success) {
    revalidatePath('/', 'layout')
    redirect('/library')
  } else if (needsConfirmation) {
    redirect('/login?message=' + encodeURIComponent('Please check your email to confirm your account before logging in.'))
  } else {
    redirect('/register?error=' + encodeURIComponent(errorMessage || 'Registration failed'))
  }
}

/**
 * Simple logout handler
 */
export async function logout() {
  try {
    const supabase = await createClient()
    await supabase.auth.signOut()
  } catch (err: any) {
    if (err.digest?.includes('NEXT_REDIRECT') || err.message === 'NEXT_REDIRECT') {
      throw err
    }
    console.error('Logout error:', err)
  } finally {
    revalidatePath('/', 'layout')
    redirect('/')
  }
}
