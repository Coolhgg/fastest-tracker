"use client"

import { useState, useEffect, useCallback, useRef } from "react"
import { Button } from "@/components/ui/button"
import { MessageSquare, Heart, Share2, BookOpen, Loader2, Filter, Users, TrendingUp, Clock, Zap } from "lucide-react"
import Link from "next/link"
import { Skeleton } from "@/components/ui/skeleton"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"

interface Activity {
  id: string
  type: string
  created_at: string
  metadata?: any
  user?: {
    id: string
    username: string
    avatar_url: string | null
  }
  series?: {
    id: string
    title: string
    cover_url: string | null
  }
}

interface FeedEntry {
  id: string;
  series: {
    id: string;
    title: string;
    cover_url: string | null;
    content_rating: string | null;
    status: string | null;
    type: string;
  };
  chapter_number: number;
  chapter_title: string | null;
  volume_number: number | null;
  is_unseen: boolean;
  sources: {
    name: string;
    url: string;
    discovered_at: string;
  }[];
  first_discovered_at: string;
  last_updated_at: string;
}

type FeedFilter = "all" | "following" | "global" | "releases"

function ActivitySkeleton() {
  return (
    <div className="space-y-8">
      {[...Array(5)].map((_, i) => (
        <div key={i} className="space-y-4">
          <div className="flex items-center gap-3">
            <Skeleton className="size-10 rounded-full" />
            <div className="space-y-2">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-3 w-16" />
            </div>
          </div>
          <Skeleton className="h-24 w-full rounded-3xl" />
        </div>
      ))}
    </div>
  )
}

export default function FeedPage() {
  const [activities, setActivities] = useState<Activity[]>([])
  const [releases, setReleases] = useState<FeedEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [filter, setFilter] = useState<FeedFilter>("following")
  const [hasMore, setHasMore] = useState(true)
  const [offset, setOffset] = useState(0)
  const [cursor, setCursor] = useState<string | null>(null)
  
  const observerTarget = useRef<HTMLDivElement>(null)

  const fetchActivities = useCallback(async (reset = false) => {
    if (filter === "releases") {
      const currentCursor = reset ? null : cursor
      
      if (reset) {
        setLoading(true)
        setCursor(null)
      } else {
        setLoadingMore(true)
      }

      try {
        const params = new URLSearchParams()
        if (currentCursor) params.set("cursor", currentCursor)
        params.set("limit", "20")

        const res = await fetch(`/api/feed/activity?${params.toString()}`)
        if (res.ok) {
          const data = await res.json()
          const items = data.entries || []
          
          if (reset) {
            setReleases(items)
          } else {
            setReleases((prev) => [...prev, ...items])
          }
          
          setHasMore(data.has_more)
          setCursor(data.next_cursor)
        }
      } catch (error) {
        console.error("Failed to fetch releases:", error)
        toast.error("Failed to load releases")
      } finally {
        setLoading(false)
        setLoadingMore(false)
      }
      return
    }

    const currentOffset = reset ? 0 : offset
    
    if (reset) {
      setLoading(true)
      setOffset(0)
    } else {
      setLoadingMore(true)
    }

    try {
      const params = new URLSearchParams()
      params.set("type", filter)
      params.set("offset", currentOffset.toString())
      params.set("limit", "20")

      const res = await fetch(`/api/feed?${params.toString()}`)
      if (res.ok) {
        const data = await res.json()
        const items = data.items || []
        
        if (reset) {
          setActivities(items)
        } else {
          setActivities((prev) => [...prev, ...items])
        }
        
        setHasMore(items.length === 20)
        setOffset(currentOffset + items.length)
      }
    } catch (error) {
      console.error("Failed to fetch feed:", error)
      toast.error("Failed to load feed")
    } finally {
      setLoading(false)
      setLoadingMore(false)
    }
  }, [filter, offset, cursor])

  useEffect(() => {
    fetchActivities(true)
  }, [filter])

  // Mark releases as seen when viewing the releases tab
  useEffect(() => {
    if (filter === "releases" && releases.length > 0) {
      const mostRecent = releases[0].first_discovered_at
      
      const markAsSeen = async () => {
        try {
          await fetch("/api/feed/seen", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ last_seen_at: mostRecent })
          })
        } catch (err) {
          console.error("Failed to mark feed as seen:", err)
        }
      }
      
      // Debounce slightly to avoid excessive calls
      const timer = setTimeout(markAsSeen, 2000)
      return () => clearTimeout(timer)
    }
  }, [filter, releases])

  useEffect(() => {
    if (!observerTarget.current || loading || !hasMore || loadingMore) return

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && hasMore && !loadingMore) {
          fetchActivities(false)
        }
      },
      { threshold: 0.1 }
    )

    observer.observe(observerTarget.current)
    return () => observer.disconnect()
  }, [hasMore, loadingMore, loading, fetchActivities])

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    const diffHours = Math.floor(diffMs / 3600000)
    const diffDays = Math.floor(diffMs / 86400000)

    if (diffMins < 1) return "Just now"
    if (diffMins < 60) return `${diffMins}m ago`
    if (diffHours < 24) return `${diffHours}h ago`
    if (diffDays < 7) return `${diffDays}d ago`
    return date.toLocaleDateString()
  }

  const getActivityText = (activity: Activity) => {
    switch (activity.type) {
      case "chapter_read":
        return `Read chapter ${activity.metadata?.chapter_number || "?"}`
      case "series_added":
        return "Added to library"
      case "level_up":
        return `Reached level ${activity.metadata?.level || "?"}`
      case "achievement_unlocked":
        return `Unlocked: ${activity.metadata?.achievement_name || "Achievement"}`
      default:
        return activity.type.replace(/_/g, " ")
    }
  }

  const handleShare = (activity: Activity) => {
    if (activity.series) {
      const url = `${window.location.origin}/series/${activity.series.id}`
      navigator.clipboard.writeText(url)
      toast.success("Link copied to clipboard!")
    }
  }

  return (
    <div className="p-6 space-y-8 max-w-2xl mx-auto pb-24">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">Social Feed</h1>
          <p className="text-zinc-500 text-sm">See what your friends are reading</p>
        </div>
        <Link href="/friends">
          <Button variant="outline" className="rounded-full border-zinc-200 dark:border-zinc-800">
            <Users className="size-4 mr-2" />
            Find Friends
          </Button>
        </Link>
      </div>

      <div className="flex items-center gap-2 p-1 bg-zinc-100 dark:bg-zinc-900 rounded-2xl border border-zinc-200 dark:border-zinc-800">
        <Button
          variant={filter === "following" ? "default" : "ghost"}
          size="sm"
          className="rounded-xl flex-1"
          onClick={() => setFilter("following")}
        >
          <Users className="size-4 mr-2" />
          Following
        </Button>
        <Button
          variant={filter === "global" ? "default" : "ghost"}
          size="sm"
          className="rounded-xl flex-1"
          onClick={() => setFilter("global")}
        >
          <TrendingUp className="size-4 mr-2" />
          Global
        </Button>
        <Button
          variant={filter === "all" ? "default" : "ghost"}
          size="sm"
          className="rounded-xl flex-1"
          onClick={() => setFilter("all")}
        >
          <Clock className="size-4 mr-2" />
          All
        </Button>
          <Button
            variant={filter === "releases" ? "default" : "ghost"}
            size="sm"
            className="rounded-xl flex-1"
            onClick={() => setFilter("releases")}
          >
            <Zap className="size-4 mr-2" />
            Releases
          </Button>
        </div>

        {loading ? (
          <ActivitySkeleton />
        ) : filter === "releases" ? (
          <div className="space-y-8">
            {releases.length > 0 ? (
              releases.map((release) => (
                <div key={release.id} className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="size-10 rounded-xl bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center text-blue-600">
                        <Zap className="size-5" />
                      </div>
                      <div>
                        <p className="text-sm font-bold flex items-center gap-2">
                          New Release
                          {release.is_unseen && (
                            <Badge className="bg-blue-500 hover:bg-blue-600 text-[8px] h-4 px-1 rounded-sm uppercase">New</Badge>
                          )}
                        </p>
                        <p className="text-[10px] text-zinc-500 font-medium">
                          {formatDate(release.first_discovered_at)}
                        </p>
                      </div>
                    </div>
                  </div>

                  <Link href={`/series/${release.series.id}`}>
                    <div className="bg-zinc-50 dark:bg-zinc-900/50 rounded-3xl border border-zinc-100 dark:border-zinc-800 p-4 flex gap-4 hover:border-zinc-300 dark:hover:border-zinc-700 transition-colors">
                      <div className="size-20 shrink-0 rounded-xl overflow-hidden border border-zinc-200 dark:border-zinc-800">
                        {release.series.cover_url ? (
                          <img src={release.series.cover_url} className="h-full w-full object-cover" alt="" />
                        ) : (
                          <div className="h-full w-full bg-zinc-200 dark:bg-zinc-800 flex items-center justify-center">
                            <BookOpen className="size-6 text-zinc-400" />
                          </div>
                        )}
                      </div>
                      <div className="flex-1 space-y-2 py-1">
                        <h3 className="font-bold text-sm leading-tight line-clamp-1">{release.series.title}</h3>
                        <p className="text-xs font-bold text-zinc-900 dark:text-zinc-100">
                          Chapter {release.chapter_number}
                          {release.chapter_title && <span className="text-zinc-500 font-normal ml-1">- {release.chapter_title}</span>}
                        </p>
                        <div className="flex flex-wrap gap-1">
                          {release.sources.map((source) => (
                            <Badge key={source.name} variant="outline" className="text-[9px] h-4 px-1 bg-zinc-100 dark:bg-zinc-800 border-zinc-200 dark:border-zinc-700">
                              {source.name}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  </Link>
                </div>
              ))
            ) : (
              <div className="text-center py-24">
                <p className="text-zinc-500">No releases found.</p>
              </div>
            )}
            <div ref={observerTarget} className="flex justify-center py-8">
              {loadingMore && <Loader2 className="size-6 animate-spin text-zinc-400" />}
            </div>
          </div>
        ) : activities.length > 0 ? (
        <div className="space-y-8">
          {activities.map((activity) => (
            <div key={activity.id} className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Link href={`/users/${activity.user?.username}`}>
                    <div className="size-10 rounded-full bg-zinc-100 dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-800 flex items-center justify-center overflow-hidden hover:ring-2 hover:ring-zinc-900 dark:hover:ring-zinc-50 transition-all">
                      {activity.user?.avatar_url ? (
                        <img src={activity.user.avatar_url} className="h-full w-full object-cover" alt="" />
                      ) : (
                        <span className="text-sm font-bold text-zinc-500 uppercase">{activity.user?.username?.[0]}</span>
                      )}
                    </div>
                  </Link>
                  <div>
                    <p className="text-sm font-bold">
                      <Link href={`/users/${activity.user?.username}`} className="hover:underline">
                        {activity.user?.username}
                      </Link>
                    </p>
                    <p className="text-[10px] text-zinc-500 font-medium">
                      {formatDate(activity.created_at)}
                    </p>
                  </div>
                </div>
                <div className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest px-2 py-1 bg-zinc-100 dark:bg-zinc-900 rounded-full">
                  {activity.type.replace(/_/g, " ")}
                </div>
              </div>

              {activity.series && (
                <Link href={`/series/${activity.series.id}`}>
                  <div className="bg-zinc-50 dark:bg-zinc-900/50 rounded-3xl border border-zinc-100 dark:border-zinc-800 p-4 flex gap-4 hover:border-zinc-300 dark:hover:border-zinc-700 transition-colors">
                    <div className="size-20 shrink-0 rounded-xl overflow-hidden border border-zinc-200 dark:border-zinc-800">
                      {activity.series.cover_url ? (
                        <img src={activity.series.cover_url} className="h-full w-full object-cover" alt="" />
                      ) : (
                        <div className="h-full w-full bg-zinc-200 dark:bg-zinc-800 flex items-center justify-center">
                          <BookOpen className="size-6 text-zinc-400" />
                        </div>
                      )}
                    </div>
                    <div className="flex-1 space-y-2 py-1">
                      <h3 className="font-bold text-sm leading-tight">{activity.series.title}</h3>
                      <p className="text-xs text-zinc-600 dark:text-zinc-400">
                        {getActivityText(activity)}
                      </p>
                      <span className="inline-block text-[10px] font-bold uppercase tracking-wider text-blue-500">
                        View Series →
                      </span>
                    </div>
                  </div>
                </Link>
              )}

              {!activity.series && (
                <div className="bg-zinc-50 dark:bg-zinc-900/50 rounded-3xl border border-zinc-100 dark:border-zinc-800 p-4">
                  <p className="text-sm text-zinc-600 dark:text-zinc-400">
                    {getActivityText(activity)}
                  </p>
                </div>
              )}

              <div className="flex items-center gap-6 px-2">
                <button className="flex items-center gap-1.5 text-zinc-500 hover:text-red-500 transition-colors">
                  <Heart className="size-4" />
                  <span className="text-xs font-bold">{Math.floor(Math.random() * 20)}</span>
                </button>
                <button className="flex items-center gap-1.5 text-zinc-500 hover:text-blue-500 transition-colors">
                  <MessageSquare className="size-4" />
                  <span className="text-xs font-bold">{Math.floor(Math.random() * 5)}</span>
                </button>
                <button 
                  className="flex items-center gap-1.5 text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-50 transition-colors ml-auto"
                  onClick={() => handleShare(activity)}
                >
                  <Share2 className="size-4" />
                </button>
              </div>
            </div>
          ))}

          <div ref={observerTarget} className="flex justify-center py-8">
            {loadingMore && <Loader2 className="size-6 animate-spin text-zinc-400" />}
            {!hasMore && activities.length > 0 && (
              <p className="text-zinc-500 text-sm">You're all caught up!</p>
            )}
          </div>
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-24 text-center space-y-4">
          <div className="size-20 rounded-full bg-zinc-50 dark:bg-zinc-900 flex items-center justify-center text-zinc-300">
            <BookOpen className="size-10" />
          </div>
          <div className="space-y-2">
            <h3 className="text-xl font-bold">
              {filter === "following" ? "Your feed is empty" : "No activity yet"}
            </h3>
            <p className="text-zinc-500 dark:text-zinc-400 max-w-xs mx-auto">
              {filter === "following" 
                ? "Follow other readers to see what they're tracking and reading."
                : "Be the first to start reading and tracking manga!"}
            </p>
          </div>
          {filter === "following" && (
            <Link href="/friends">
              <Button className="bg-zinc-900 text-zinc-50 hover:bg-zinc-800 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-zinc-200 rounded-full px-8">
                Find Friends
              </Button>
            </Link>
          )}
        </div>
      )}
    </div>
  )
}
