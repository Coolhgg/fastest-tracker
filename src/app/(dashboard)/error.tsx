"use client"

import { useEffect } from "react"
import { Button } from "@/components/ui/button"
import { AlertTriangle, RefreshCw, Home } from "lucide-react"
import Link from "next/link"

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    console.error("Dashboard error:", error)
  }, [error])

  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center p-6 text-center">
      <div className="size-20 rounded-full bg-red-50 dark:bg-red-950/30 flex items-center justify-center mb-6">
        <AlertTriangle className="size-10 text-red-500" />
      </div>
      
      <h2 className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50 mb-2">
        Something went wrong
      </h2>
      <p className="text-zinc-500 dark:text-zinc-400 max-w-md mb-8">
        We encountered an unexpected error. This has been logged and we&apos;ll look into it.
      </p>
      
      <div className="flex items-center gap-4">
        <Button
          onClick={reset}
          className="rounded-full px-6 bg-zinc-900 dark:bg-zinc-50 text-zinc-50 dark:text-zinc-900"
        >
          <RefreshCw className="size-4 mr-2" />
          Try again
        </Button>
        <Link href="/library">
          <Button variant="outline" className="rounded-full px-6 border-zinc-200 dark:border-zinc-800">
            <Home className="size-4 mr-2" />
            Go to Library
          </Button>
        </Link>
      </div>
      
      {error.digest && (
        <p className="mt-8 text-xs text-zinc-400 font-mono">
          Error ID: {error.digest}
        </p>
      )}
    </div>
  )
}
