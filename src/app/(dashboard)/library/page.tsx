"use client"

import { useState, useEffect, useCallback, useMemo, memo, Suspense } from "react"
import { Button } from "@/components/ui/button"
import { Plus, Search, Grid2X2, List as ListIcon, BookOpen, Star, ArrowUpDown, AlertCircle, FileText, Loader2 } from "lucide-react"
import { Input } from "@/components/ui/input"
import Link from "next/link"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useRouter, useSearchParams } from "next/navigation"
import { useDebounce, useIntersectionObserver } from "@/hooks/use-performance"
import { toast } from "sonner"
import { NSFWCover } from "@/components/ui/nsfw-cover"
import { CSVImport } from "@/components/library/CSVImport"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"

interface LibraryEntry {
  id: string
  series_id: string
  status: string
  last_read_chapter: number | null
  user_rating: number | null
  updated_at: string
  series: {
    id: string
    title: string
    cover_url: string | null
    type: string
    status: string
    content_rating: string | null
  } | null
}

interface LibraryStats {
  all: number
  reading: number
  completed: number
  planning: number
  dropped: number
  paused: number
}

function LibrarySkeleton({ viewMode }: { viewMode: "grid" | "list" }) {
  if (viewMode === "list") {
    return (
      <div className="space-y-3">
        {[...Array(8)].map((_, i) => (
          <div key={i} className="flex items-center gap-4 p-4 rounded-2xl border border-zinc-100 dark:border-zinc-800">
            <Skeleton className="size-16 rounded-xl shrink-0" />
            <div className="flex-1 space-y-2">
              <Skeleton className="h-4 w-48" />
              <Skeleton className="h-3 w-24" />
            </div>
            <Skeleton className="h-6 w-20 rounded-full" />
          </div>
        ))}
      </div>
    )
  }

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-6">
      {[...Array(12)].map((_, i) => (
        <div key={i} className="space-y-3">
          <Skeleton className="aspect-[3/4] rounded-2xl" />
          <div className="space-y-2 px-1">
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-3 w-16" />
          </div>
        </div>
      ))}
    </div>
  )
}

// Memoized grid item for performance
const LibraryGridItem = memo(function LibraryGridItem({ entry }: { entry: LibraryEntry }) {
  return (
    <Link href={`/series/${entry.series_id}`} className="group relative space-y-3">
      <div className="overflow-hidden rounded-2xl bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 transition-all group-hover:ring-2 group-hover:ring-zinc-900 dark:group-hover:ring-zinc-50 relative shadow-sm group-hover:shadow-md">
        <NSFWCover
          src={entry.series?.cover_url}
          alt={entry.series?.title || "Series cover"}
          contentRating={entry.series?.content_rating}
          className="transition-transform duration-500 group-hover:scale-110"
          size="512"
        />
        <div className="absolute top-2 right-2 bg-zinc-900/80 backdrop-blur-md text-zinc-50 text-[10px] font-bold px-2 py-1 rounded-lg">
          CH {entry.last_read_chapter || 0}
        </div>
        <Badge
          className={`absolute bottom-2 left-2 text-[10px] rounded-lg ${
            entry.status === "reading"
              ? "bg-green-500 hover:bg-green-600"
              : entry.status === "completed"
                ? "bg-blue-500 hover:bg-blue-600"
                : entry.status === "planning"
                  ? "bg-amber-500 hover:bg-amber-600"
                  : "bg-zinc-500 hover:bg-zinc-600"
          }`}
        >
          {entry.status}
        </Badge>
      </div>
      <div className="space-y-1 px-1">
        <h3 className="font-bold text-sm leading-tight truncate">{entry.series?.title}</h3>
        <div className="flex items-center gap-2 text-[10px] text-zinc-500 dark:text-zinc-400 font-medium">
          <span className="capitalize">{entry.series?.type}</span>
          {entry.user_rating && (
            <span className="flex items-center gap-0.5">
              <Star className="size-3 fill-yellow-500 text-yellow-500" />
              {entry.user_rating}
            </span>
          )}
        </div>
      </div>
    </Link>
  )
})

// Memoized list item for performance
const LibraryListItem = memo(function LibraryListItem({ entry }: { entry: LibraryEntry }) {
  return (
    <Link
      href={`/series/${entry.series_id}`}
      className="flex items-center gap-4 p-4 rounded-2xl border border-zinc-100 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-900/50 transition-colors group"
    >
      <div className="size-16 rounded-xl overflow-hidden shrink-0 bg-zinc-100 dark:bg-zinc-800">
        <NSFWCover
          src={entry.series?.cover_url}
          alt={entry.series?.title || "Series cover"}
          contentRating={entry.series?.content_rating}
          aspectRatio="aspect-square"
          showBadge={false}
          size="256"
        />
      </div>
      <div className="flex-1 min-w-0">
        <h3 className="font-bold text-sm truncate group-hover:text-zinc-900 dark:group-hover:text-zinc-50">
          {entry.series?.title}
        </h3>
        <div className="flex items-center gap-3 text-xs text-zinc-500 mt-1">
          <span className="capitalize">{entry.series?.type}</span>
          <span>Chapter {entry.last_read_chapter || 0}</span>
          {entry.user_rating && (
            <span className="flex items-center gap-0.5">
              <Star className="size-3 fill-yellow-500 text-yellow-500" />
              {entry.user_rating}
            </span>
          )}
        </div>
      </div>
      <Badge
        className={`text-[10px] rounded-full ${
          entry.status === "reading"
            ? "bg-green-500 hover:bg-green-600"
            : entry.status === "completed"
              ? "bg-blue-500 hover:bg-blue-600"
              : entry.status === "planning"
                ? "bg-amber-500 hover:bg-amber-600"
                : "bg-zinc-500 hover:bg-zinc-600"
        }`}
      >
        {entry.status}
      </Badge>
    </Link>
  )
})

function LibraryPageContent() {
  const router = useRouter()
  const searchParams = useSearchParams()
  
  const [entries, setEntries] = useState<LibraryEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [viewMode, setViewMode] = useState<"grid" | "list">("grid")
  const [searchQuery, setSearchQuery] = useState(searchParams.get("q") || "")
  const [filterStatus, setFilterStatus] = useState(searchParams.get("status") || "all")
  const [sortBy, setSortBy] = useState(searchParams.get("sort") || "updated")
  
  // Pagination state
  const [offset, setOffset] = useState(0)
  const [hasMore, setHasMore] = useState(false)
  const [stats, setStats] = useState<LibraryStats>({
    all: 0,
    reading: 0,
    completed: 0,
    planning: 0,
    dropped: 0,
    paused: 0
  })

  // Debounce search query for performance
  const debouncedSearchQuery = useDebounce(searchQuery, 300)

  const fetchLibrary = useCallback(async (isInitial = true) => {
    if (isInitial) {
      setLoading(true)
      setOffset(0)
    } else {
      setLoadingMore(true)
    }
    
    setError(null)
    try {
      const currentOffset = isInitial ? 0 : offset
      const params = new URLSearchParams()
      if (debouncedSearchQuery) params.set("q", debouncedSearchQuery)
      if (filterStatus && filterStatus !== "all") params.set("status", filterStatus)
      if (sortBy) params.set("sort", sortBy)
      params.set("limit", "100")
      params.set("offset", currentOffset.toString())

      const res = await fetch(`/api/library?${params.toString()}`)
      if (res.ok) {
        const data = await res.json()
        if (isInitial) {
          setEntries(data.entries || [])
        } else {
          setEntries(prev => [...prev, ...(data.entries || [])])
        }
        
        if (data.stats) {
          setStats(data.stats)
        }
        
        setHasMore(data.pagination?.hasMore || false)
        if (!isInitial) {
          setOffset(prev => prev + (data.entries?.length || 0))
        } else {
          setOffset(data.entries?.length || 0)
        }
      } else if (res.status === 401) {
        setError("Please sign in to view your library")
      } else {
        setError("Failed to load library")
      }
    } catch (err) {
      console.error("Failed to fetch library:", err)
      setError("Something went wrong. Please try again.")
      toast.error("Failed to load library")
    } finally {
      if (isInitial) setLoading(false)
      else setLoadingMore(false)
    }
  }, [debouncedSearchQuery, filterStatus, sortBy, offset])

  useEffect(() => {
    fetchLibrary(true)
  }, [debouncedSearchQuery, filterStatus, sortBy])

  // Infinite scroll observer
  const { setRef, isIntersecting } = useIntersectionObserver({
    threshold: 0.1,
    rootMargin: '100px',
  })

  useEffect(() => {
    if (isIntersecting && hasMore && !loading && !loadingMore) {
      fetchLibrary(false)
    }
  }, [isIntersecting, hasMore, loading, loadingMore, fetchLibrary])

  const handleSearch = useCallback((e: React.FormEvent) => {
    e.preventDefault()
    const params = new URLSearchParams()
    if (searchQuery) params.set("q", searchQuery)
    if (filterStatus !== "all") params.set("status", filterStatus)
    if (sortBy !== "updated") params.set("sort", sortBy)
    router.push(`/library?${params.toString()}`)
  }, [searchQuery, filterStatus, sortBy, router])

  const handleStatusChange = useCallback((status: string) => {
    setFilterStatus(status)
    const params = new URLSearchParams()
    if (searchQuery) params.set("q", searchQuery)
    if (status !== "all") params.set("status", status)
    if (sortBy !== "updated") params.set("sort", sortBy)
    router.push(`/library?${params.toString()}`)
  }, [searchQuery, sortBy, router])

  if (error) {
    return (
      <div className="p-6 space-y-8 max-w-7xl mx-auto pb-24">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">Library</h1>
          <p className="text-zinc-500 dark:text-zinc-400">Manage your reading progress and updates</p>
        </div>
        <div className="flex flex-col items-center justify-center py-24 text-center space-y-4">
          <div className="size-20 rounded-full bg-red-50 dark:bg-red-950/30 flex items-center justify-center">
            <AlertCircle className="size-10 text-red-500" />
          </div>
          <div className="space-y-2">
            <h3 className="text-xl font-bold">{error}</h3>
            <Button onClick={fetchLibrary} variant="outline" className="rounded-full">
              Try again
            </Button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-8 max-w-7xl mx-auto pb-24">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">Library</h1>
          <p className="text-zinc-500 dark:text-zinc-400">Manage your reading progress and updates</p>
        </div>
        <div className="flex items-center gap-2">
          <Dialog>
            <DialogTrigger asChild>
              <Button variant="outline" className="rounded-full px-6 border-zinc-200 dark:border-zinc-800">
                <FileText className="size-4 mr-2 text-zinc-500" />
                Import CSV
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-md rounded-3xl">
              <DialogHeader>
                <DialogTitle>Import from CSV</DialogTitle>
                <DialogDescription>
                  Upload a CSV file to import your reading progress from other platforms.
                </DialogDescription>
              </DialogHeader>
              <CSVImport onComplete={fetchLibrary} />
            </DialogContent>
          </Dialog>

          <Link href="/discover">
            <Button className="bg-zinc-900 text-zinc-50 hover:bg-zinc-800 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-zinc-200 rounded-full px-6">
              <Plus className="size-4 mr-2" />
              Add Series
            </Button>
          </Link>
        </div>

      </div>

      <div className="flex flex-col md:flex-row items-center justify-between gap-4 bg-zinc-50 dark:bg-zinc-900/50 p-4 rounded-2xl border border-zinc-100 dark:border-zinc-800 shadow-sm">
        <form onSubmit={handleSearch} className="flex items-center gap-4 w-full md:w-auto">
          <div className="relative flex-1 md:w-80">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-zinc-400" />
            <Input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search library..."
              className="pl-10 bg-white dark:bg-zinc-950 border-zinc-200 dark:border-zinc-800 rounded-xl h-11"
            />
          </div>
          <Button type="submit" variant="secondary" className="rounded-xl h-11">
            Search
          </Button>
        </form>

        <div className="flex items-center gap-4 w-full md:w-auto overflow-x-auto pb-2 md:pb-0">
            <div className="flex items-center gap-1 bg-zinc-100 dark:bg-zinc-800 p-1 rounded-xl border border-zinc-200 dark:border-zinc-700">
              <Button
                variant={filterStatus === "all" ? "secondary" : "ghost"}
                size="sm"
                className="rounded-lg text-xs h-8 px-3"
                onClick={() => handleStatusChange("all")}
              >
                All ({stats.all})
              </Button>
              <Button
                variant={filterStatus === "reading" ? "secondary" : "ghost"}
                size="sm"
                className="rounded-lg text-xs h-8 px-3"
                onClick={() => handleStatusChange("reading")}
              >
                Reading ({stats.reading})
              </Button>
              <Button
                variant={filterStatus === "completed" ? "secondary" : "ghost"}
                size="sm"
                className="rounded-lg text-xs h-8 px-3"
                onClick={() => handleStatusChange("completed")}
              >
                Done ({stats.completed})
              </Button>
              <Button
                variant={filterStatus === "planning" ? "secondary" : "ghost"}
                size="sm"
                className="rounded-lg text-xs h-8 px-3"
                onClick={() => handleStatusChange("planning")}
              >
                Plan ({stats.planning})
              </Button>
            </div>


          <Select value={sortBy} onValueChange={setSortBy}>
            <SelectTrigger className="w-[140px] h-8 rounded-lg text-xs border-zinc-200 dark:border-zinc-700">
              <ArrowUpDown className="size-3 mr-1" />
              <SelectValue placeholder="Sort by" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="updated">Last Updated</SelectItem>
              <SelectItem value="title">Title</SelectItem>
              <SelectItem value="rating">Rating</SelectItem>
              <SelectItem value="added">Date Added</SelectItem>
            </SelectContent>
          </Select>

          <div className="flex items-center gap-1 bg-zinc-100 dark:bg-zinc-800 p-1 rounded-xl border border-zinc-200 dark:border-zinc-700 shrink-0">
            <Button
              variant="ghost"
              size="icon"
              className={`size-8 rounded-lg ${viewMode === "grid" ? "bg-white dark:bg-zinc-700 shadow-sm" : "text-zinc-500"}`}
              onClick={() => setViewMode("grid")}
            >
              <Grid2X2 className="size-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className={`size-8 rounded-lg ${viewMode === "list" ? "bg-white dark:bg-zinc-700 shadow-sm" : "text-zinc-500"}`}
              onClick={() => setViewMode("list")}
            >
              <ListIcon className="size-4" />
            </Button>
          </div>
        </div>
      </div>

      {loading ? (
        <LibrarySkeleton viewMode={viewMode} />
      ) : entries.length > 0 ? (
        <>
          {viewMode === "grid" ? (
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-6">
              {entries.map((entry) => (
                <LibraryGridItem key={entry.id} entry={entry} />
              ))}
            </div>
          ) : (
            <div className="space-y-3">
              {entries.map((entry) => (
                <LibraryListItem key={entry.id} entry={entry} />
              ))}
            </div>
          )}

          {/* Infinite Scroll Target */}
          <div 
            ref={setRef} 
            className="w-full py-12 flex items-center justify-center"
          >
            {loadingMore && (
              <div className="flex flex-col items-center gap-2 text-zinc-500">
                <Loader2 className="size-6 animate-spin" />
                <span className="text-sm font-medium">Loading more...</span>
              </div>
            )}
            {!hasMore && entries.length > 0 && (
              <p className="text-sm text-zinc-400 font-medium italic">
                You've reached the end of your library
              </p>
            )}
          </div>
        </>
      ) : (
        <div className="flex flex-col items-center justify-center py-24 text-center space-y-4">
          <div className="size-20 rounded-full bg-zinc-50 dark:bg-zinc-900 flex items-center justify-center text-zinc-300">
            <BookOpen className="size-10" />
          </div>
          <div className="space-y-2">
            <h3 className="text-xl font-bold">Your library is empty</h3>
            <p className="text-zinc-500 dark:text-zinc-400 max-w-xs mx-auto">
              Start by adding some manga or search for your favorite series to track them.
            </p>
          </div>
          <Link href="/discover">
            <Button className="bg-zinc-900 text-zinc-50 hover:bg-zinc-800 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-zinc-200 rounded-full px-8">
              Explore Series
            </Button>
          </Link>
        </div>
      )}
    </div>
  )
}

function LibraryPageSkeleton() {
  return (
    <div className="p-6 space-y-8 max-w-7xl mx-auto pb-24">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <Skeleton className="h-9 w-32" />
          <Skeleton className="h-5 w-64 mt-2" />
        </div>
        <Skeleton className="h-10 w-32 rounded-full" />
      </div>
      <Skeleton className="h-16 rounded-2xl" />
      <LibrarySkeleton viewMode="grid" />
    </div>
  )
}

export default function LibraryPage() {
  return (
    <Suspense fallback={<LibraryPageSkeleton />}>
      <LibraryPageContent />
    </Suspense>
  )
}
