import { NextResponse } from 'next/server'
// The client you created from the Server-Side Auth instructions
import { createClient } from '@/lib/supabase/server'
import { checkRateLimit, getClientIp } from "@/lib/api-utils"

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url)
    const code = searchParams.get('code')
    // if "next" is in search params, use it as the redirection URL
    let next = searchParams.get('next') ?? '/'

    // SECURITY: Validate "next" to prevent open redirect vulnerabilities
    // Must be a relative path starting with / and not starting with //
    if (!next.startsWith('/') || next.startsWith('//')) {
      console.warn(`[Auth] Potential open redirect attempt detected. Blocked "next" value: ${next}`)
      next = '/'
    }


  // SECURITY: Rate limit OAuth callback to prevent code brute-forcing
  const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
  if (!checkRateLimit(`oauth:${ip}`, 10, 60000)) {
    return NextResponse.redirect(`${origin}/auth/auth-code-error?error=rate_limited`)
  }

  if (code) {
    const supabase = await createClient()
    const { error } = await supabase.auth.exchangeCodeForSession(code)
    if (!error) {
      const forwardedHost = request.headers.get('x-forwarded-host') // localhost:3000
      const isLocalEnv = process.env.NODE_ENV === 'development'
      if (isLocalEnv) {
        // we can be sure that originated from localhost
        return NextResponse.redirect(`${origin}${next}`)
      } else if (forwardedHost) {
        return NextResponse.redirect(`https://${forwardedHost}${next}`)
      } else {
        return NextResponse.redirect(`${origin}${next}`)
      }
    }
  }

  // return the user to an error page with instructions
  return NextResponse.redirect(`${origin}/auth/auth-code-error`)
}
