import { PrismaClient } from '@prisma/client'

const globalForPrisma = global as unknown as { 
  prisma: PrismaClient
  prismaRead: PrismaClient | null
}

// Configure Prisma with robust connection handling
const prismaClientSingleton = () => {
  return new PrismaClient({
    log: process.env.NODE_ENV === 'development' 
      ? ['error', 'warn'] 
      : ['error'],
  })
}

// Read replica client (optional - uses DATABASE_READ_URL if configured)
const prismaReadSingleton = (): PrismaClient | null => {
  const readUrl = process.env.DATABASE_READ_URL
  if (!readUrl) return null
  
  return new PrismaClient({
    log: process.env.NODE_ENV === 'development' 
      ? ['error', 'warn'] 
      : ['error'],
    datasources: {
      db: { url: readUrl }
    }
  })
}

// Primary write client (always uses DATABASE_URL)
export const prisma = globalForPrisma.prisma ?? prismaClientSingleton()

// Read replica client (falls back to primary if not configured)
export const prismaRead = globalForPrisma.prismaRead ?? prismaReadSingleton() ?? prisma

// Convenience: check if read replica is active
export const hasReadReplica = !!process.env.DATABASE_READ_URL

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma
  globalForPrisma.prismaRead = prismaRead === prisma ? null : prismaRead
}

/**
 * Wrapper for Prisma queries with retry logic for transient connection errors
 */
export async function withRetry<T>(
  operation: () => Promise<T>,
  maxRetries = 3,
  baseDelayMs = 200
): Promise<T> {
  let lastError: Error | null = null
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await operation()
    } catch (error: any) {
      lastError = error
      
      // Check if error is transient and worth retrying
      const isTransient = isTransientError(error)
      
      // Log for debugging
      if (attempt === 0) {
        console.log('[Prisma] Error type:', error?.constructor?.name, 'name:', error?.name, 'code:', error?.code)
        console.log('[Prisma] isTransient:', isTransient)
      }
      
      if (!isTransient || attempt === maxRetries - 1) {
        throw error
      }
      
      // Exponential backoff with jitter
      const delay = baseDelayMs * Math.pow(2, attempt) + Math.random() * 100
      await new Promise(resolve => setTimeout(resolve, delay))
      
      console.warn(`[Prisma] Retry attempt ${attempt + 1}/${maxRetries}`)
    }
  }
  
  throw lastError
}

/**
 * Check if a Prisma error is transient (connection-related)
 */
export function isTransientError(error: any): boolean {
  if (!error) return false
  
  // Get the full error message and convert to lowercase for checking
  const errorMessage = (error.message || '').toLowerCase()
  const errorCode = error.code || ''
  const errorName = error.name || error.constructor?.name || ''
  
  // SECURITY FIX: Check non-transient errors FIRST before transient patterns
  // Authentication errors should NOT be retried
  const nonTransientPatterns = [
    'password authentication failed',
    'authentication failed',
    'invalid password',
    'access denied',
    'permission denied',
    'role .* does not exist',
    'database .* does not exist',
    'invalid credentials',
  ]

  for (const pattern of nonTransientPatterns) {
    if (pattern.includes('.*')) {
      // Regex pattern
      if (new RegExp(pattern, 'i').test(errorMessage)) {
        return false
      }
    } else if (errorMessage.includes(pattern)) {
      return false
    }
  }

  // Non-transient Prisma error codes
  const nonTransientCodes = ['P1000', 'P1003'] // Auth failed, DB doesn't exist
  if (nonTransientCodes.includes(errorCode)) {
    return false
  }

  // Connection-related errors that may be transient
  const transientPatterns = [
    'circuit breaker',
    "can't reach database",
    'cannot reach database',
    'connection refused',
    'connection reset',
    'connection timed out',
    'econnrefused',
    'econnreset',
    'etimedout',
    'unable to establish connection',
    'connection pool timeout',
    'too many connections',
    'tenant or user not found',  // Supabase pooler provisioning error
    'unable to establish connection to upstream',
    'pool_timeout',
    'server closed the connection unexpectedly',
    'prepared statement',
    'ssl connection has been closed unexpectedly',
  ]
  
  // Prisma error codes that indicate connection issues
  const transientCodes = ['P1001', 'P1002', 'P1008', 'P1017', 'P2024', 'P2028']
  
  // Check error name/type - Prisma initialization errors are transient ONLY if not auth-related
  const isInitError = 
    errorName.includes('PrismaClientInitializationError') ||
    errorName.includes('PrismaClientKnownRequestError') ||
    errorMessage.includes('prisma') && (
      errorMessage.includes('initialization') ||
      errorMessage.includes('invocation')
    )
  
  const patternMatch = transientPatterns.some(pattern => errorMessage.includes(pattern))
  const codeMatch = transientCodes.includes(errorCode)
  
  return isInitError || patternMatch || codeMatch
}

/**
 * Safe query wrapper that handles connection errors gracefully
 */
export async function safeQuery<T>(
  operation: () => Promise<T>,
  fallback?: T
): Promise<{ data: T | null; error: Error | null }> {
  try {
    const data = await withRetry(operation)
    return { data, error: null }
  } catch (error: any) {
    console.error('Database query error:', error.message?.slice(0, 200))
    return { data: fallback ?? null, error }
  }
}

// Graceful shutdown handler
const handleShutdown = async () => {
  await prisma.$disconnect()
}

// Only register handlers in Node.js environment (not in Edge)
if (typeof process !== 'undefined' && process.on) {
  process.on('beforeExit', handleShutdown)
  process.on('SIGINT', handleShutdown)
  process.on('SIGTERM', handleShutdown)
}
