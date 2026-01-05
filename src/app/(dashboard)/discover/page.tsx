"use client"

import { useState, useEffect, useCallback, Suspense } from "react"
import { Star, Users, Flame, BookOpen, TrendingUp } from "lucide-react"
import Link from "next/link"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { NSFWCover } from "@/components/ui/nsfw-cover"

interface Series {
  id: string
  title: string
  cover_url: string | null
  content_rating: string | null
  type: string
  status: string
  genres: string[]
  average_rating: number | null
  total_follows: number
  updated_at: string
}

function SeriesSkeleton() {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-6">
      {[...Array(6)].map((_, i) => (
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

function SeriesCard({ 
  series, 
  index, 
}: { 
  series: Series; 
  index?: number;
}) {
  return (
    <div className="group space-y-3 relative">
      <Link href={`/series/${series.id}`} className="block relative">
        <div className="overflow-hidden rounded-2xl bg-zinc-100 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 transition-all group-hover:ring-2 group-hover:ring-zinc-900 dark:group-hover:ring-zinc-50 shadow-sm group-hover:shadow-md relative">
            <NSFWCover
              src={series.cover_url}
              alt={series.title}
              contentRating={series.content_rating}
              // REGRESSION LOCK: Do NOT use forceMode="sfw" here. 
              // Discover must respect user SafeBrowsing settings.
              className="transition-transform duration-500 group-hover:scale-110"
              aspectRatio="aspect-[3/4]"
              showBadge={true}
              size="512"
            />
          {typeof index === 'number' && (
            <div className="absolute top-2 left-2 bg-zinc-900/90 backdrop-blur-sm text-white text-xs font-bold px-2 py-1 rounded-lg z-20">
              #{index + 1}
            </div>
          )}
          <Badge className="absolute top-2 right-2 capitalize text-[10px] z-20" variant="secondary">
            {series.type}
          </Badge>
        </div>
      </Link>
      <div className="space-y-1 px-1">
        <h3 className="font-bold text-sm leading-tight truncate">{series.title}</h3>
        <div className="flex items-center gap-3 text-[10px] text-zinc-500 font-medium">
          <span className="flex items-center gap-1">
            <Star className="size-3 text-yellow-500 fill-yellow-500" /> {series.average_rating || "N/A"}
          </span>
          <span className="flex items-center gap-1">
            <Users className="size-3" /> {series.total_follows >= 1000 ? `${Math.round(series.total_follows / 1000)}K` : series.total_follows}
          </span>
        </div>
      </div>
    </div>
  )
}

const DiscoverPageContent = () => {
  const [trending, setTrending] = useState<Series[]>([])
  const [popularManga, setPopularManga] = useState<Series[]>([])
  const [popularManhwa, setPopularManhwa] = useState<Series[]>([])
  const [loadingTrending, setLoadingTrending] = useState(true)
  const [loadingPopular, setLoadingPopular] = useState(true)

  const fetchTrending = useCallback(async () => {
    setLoadingTrending(true)
    try {
      const res = await fetch("/api/series/trending?limit=6")
      if (res.ok) {
        const data = await res.json()
        setTrending(data.results || [])
      }
    } catch (error) {
      console.error("Failed to fetch trending:", error)
    } finally {
      setLoadingTrending(false)
    }
  }, [])

  const fetchPopular = useCallback(async () => {
    setLoadingPopular(true)
    try {
      const [mangaRes, manhwaRes] = await Promise.all([
        fetch("/api/series/trending?type=manga&limit=6"),
        fetch("/api/series/trending?type=manhwa&limit=6"),
      ])
      
      if (mangaRes.ok) {
        const data = await mangaRes.json()
        setPopularManga(data.results || [])
      }
      if (manhwaRes.ok) {
        const data = await manhwaRes.json()
        setPopularManhwa(data.results || [])
      }
    } catch (error) {
      console.error("Failed to fetch popular:", error)
    } finally {
      setLoadingPopular(false)
    }
  }, [])

  useEffect(() => {
    fetchTrending()
    fetchPopular()
  }, [fetchTrending, fetchPopular])

  return (
    <div className="p-6 space-y-12 max-w-7xl mx-auto pb-24">
      <div className="space-y-2">
        <h1 className="text-4xl font-extrabold tracking-tight">Discover</h1>
        <p className="text-zinc-500 text-lg">Inspiration, trending, and curated discovery.</p>
      </div>

      <section className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-orange-100 dark:bg-orange-900/30">
              <Flame className="size-5 text-orange-500" />
            </div>
            <h2 className="text-2xl font-bold tracking-tight">Trending This Week</h2>
          </div>
        </div>
        {loadingTrending ? (
          <SeriesSkeleton />
        ) : trending.length > 0 ? (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-6">
            {trending.map((series, index) => (
              <SeriesCard key={series.id} series={series} index={index} />
            ))}
          </div>
        ) : (
          <div className="py-12 text-center bg-zinc-50 dark:bg-zinc-900/50 rounded-2xl border border-dashed border-zinc-200 dark:border-zinc-800">
            <p className="text-zinc-500 text-sm">No trending series found this week.</p>
          </div>
        )}
      </section>

      <section className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-100 dark:bg-blue-900/30">
              <BookOpen className="size-5 text-blue-500" />
            </div>
            <h2 className="text-2xl font-bold tracking-tight">Popular Manga</h2>
          </div>
        </div>
        {loadingPopular ? (
          <SeriesSkeleton />
        ) : popularManga.length > 0 ? (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-6">
            {popularManga.map((series) => (
              <SeriesCard key={series.id} series={series} />
            ))}
          </div>
        ) : (
          <div className="py-10 text-center bg-zinc-50 dark:bg-zinc-900/50 rounded-xl border border-dashed border-zinc-200 dark:border-zinc-800">
            <p className="text-zinc-500 text-xs">No popular manga found.</p>
          </div>
        )}
      </section>

      <section className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-100 dark:bg-purple-900/30">
              <TrendingUp className="size-5 text-purple-500" />
            </div>
            <h2 className="text-2xl font-bold tracking-tight">Popular Manhwa</h2>
          </div>
        </div>
        {loadingPopular ? (
          <SeriesSkeleton />
        ) : popularManhwa.length > 0 ? (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-6">
            {popularManhwa.map((series) => (
              <SeriesCard key={series.id} series={series} />
            ))}
          </div>
        ) : (
          <div className="py-10 text-center bg-zinc-50 dark:bg-zinc-900/50 rounded-xl border border-dashed border-zinc-200 dark:border-zinc-800">
            <p className="text-zinc-500 text-xs">No popular manhwa found.</p>
          </div>
        )}
      </section>
    </div>
  )
}

function DiscoverPageSkeleton() {
  return (
    <div className="p-6 space-y-12 max-w-7xl mx-auto pb-24">
      <div className="space-y-2">
        <Skeleton className="h-10 w-48" />
        <Skeleton className="h-6 w-72" />
      </div>
      <section className="space-y-6">
        <Skeleton className="h-8 w-48" />
        <SeriesSkeleton />
      </section>
    </div>
  )
}

export default function DiscoverPage() {
  return (
    <Suspense fallback={<DiscoverPageSkeleton />}>
      <DiscoverPageContent />
    </Suspense>
  )
}
