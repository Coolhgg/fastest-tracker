import { prisma } from './prisma'
import { getClientIp } from './api-utils'

export type AuditEvent = 
  | 'AUTH_LOGIN'
  | 'AUTH_LOGOUT'
  | 'AUTH_REGISTER'
  | 'PASSWORD_CHANGE'
  | 'SETTINGS_UPDATE'
  | 'PRIVACY_UPDATE'
  | 'SOCIAL_FOLLOW'
  | 'SOCIAL_UNFOLLOW'
  | 'ADMIN_ACTION'
  | 'API_KEY_GENERATE'

export interface AuditLogOptions {
  userId?: string
  status: 'success' | 'failure'
  metadata?: Record<string, any>
  request?: Request
}

/**
 * Records a security-relevant event to the audit log.
 */
export async function logSecurityEvent(
  event: AuditEvent,
  options: AuditLogOptions
) {
  const { userId, status, metadata, request } = options
  
  let ipAddress: string | undefined
  let userAgent: string | undefined

  if (request) {
    ipAddress = getClientIp(request)
    userAgent = request.headers.get('user-agent') || undefined
  }

  try {
    await prisma.auditLog.create({
      data: {
        user_id: userId,
        event,
        status,
        ip_address: ipAddress,
        user_agent: userAgent,
        metadata: metadata || {},
      },
    })
  } catch (error) {
    // We don't want to crash the request if audit logging fails, 
    // but we should log it to the console
    console.error('[AuditLog] Failed to record security event:', error)
  }
}
