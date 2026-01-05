"use client"

import { useState, useEffect, useCallback } from "react"
import { Button } from "@/components/ui/button"
import { Trophy, Medal, Crown, Star, Loader2, Calendar, Flame, BookOpen } from "lucide-react"
import Link from "next/link"
import { Skeleton } from "@/components/ui/skeleton"

interface LeaderboardUser {
  username: string
  avatar_url: string | null
  xp: number
  level: number
  streak_days?: number
}

type TimePeriod = "weekly" | "monthly" | "all-time"
type Category = "xp" | "streak" | "chapters"

function LeaderboardSkeleton() {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-4 items-end pt-12 pb-8">
        <div className="flex flex-col items-center space-y-4">
          <Skeleton className="size-20 rounded-3xl" />
          <Skeleton className="h-4 w-16" />
          <Skeleton className="h-24 w-full rounded-t-2xl" />
        </div>
        <div className="flex flex-col items-center space-y-4">
          <Skeleton className="size-28 rounded-3xl" />
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-32 w-full rounded-t-2xl" />
        </div>
        <div className="flex flex-col items-center space-y-4">
          <Skeleton className="size-20 rounded-3xl" />
          <Skeleton className="h-4 w-16" />
          <Skeleton className="h-20 w-full rounded-t-2xl" />
        </div>
      </div>
      <div className="space-y-2">
        {[...Array(7)].map((_, i) => (
          <Skeleton key={i} className="h-16 w-full rounded-xl" />
        ))}
      </div>
    </div>
  )
}

export default function LeaderboardPage() {
  const [users, setUsers] = useState<LeaderboardUser[]>([])
  const [loading, setLoading] = useState(true)
  const [timePeriod, setTimePeriod] = useState<TimePeriod>("all-time")
  const [category, setCategory] = useState<Category>("xp")

  const fetchLeaderboard = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams()
      params.set("period", timePeriod)
      params.set("category", category)
      params.set("limit", "50")

      const res = await fetch(`/api/leaderboard?${params.toString()}`)
      if (res.ok) {
        const data = await res.json()
        setUsers(data.users || [])
      }
    } catch (error) {
      console.error("Failed to fetch leaderboard:", error)
    } finally {
      setLoading(false)
    }
  }, [timePeriod, category])

  useEffect(() => {
    fetchLeaderboard()
  }, [fetchLeaderboard])

  const getCategoryLabel = () => {
    switch (category) {
      case "xp": return "XP"
      case "streak": return "Streak"
      case "chapters": return "Chapters"
    }
  }

  const getCategoryValue = (user: LeaderboardUser) => {
    switch (category) {
      case "xp": return user.xp.toLocaleString()
      case "streak": return `${user.streak_days || 0} days`
      case "chapters": return user.xp.toLocaleString()
    }
  }

  return (
    <div className="p-6 md:p-12 space-y-12 max-w-4xl mx-auto pb-24">
      <div className="text-center space-y-4">
        <div className="size-16 rounded-full bg-yellow-100 dark:bg-yellow-900/30 flex items-center justify-center mx-auto text-yellow-600 dark:text-yellow-500">
          <Trophy className="size-8" />
        </div>
        <h1 className="text-4xl font-black tracking-tight text-zinc-900 dark:text-zinc-50">Global Leaderboard</h1>
        <p className="text-zinc-500 dark:text-zinc-400">The most dedicated readers in the Kenmei community</p>
      </div>

      <div className="flex flex-col sm:flex-row gap-4 justify-center">
        <div className="flex items-center gap-1 p-1 bg-zinc-100 dark:bg-zinc-900 rounded-2xl border border-zinc-200 dark:border-zinc-800">
          <Button
            variant={timePeriod === "weekly" ? "default" : "ghost"}
            size="sm"
            className="rounded-xl"
            onClick={() => setTimePeriod("weekly")}
          >
            <Calendar className="size-4 mr-2" />
            This Week
          </Button>
          <Button
            variant={timePeriod === "monthly" ? "default" : "ghost"}
            size="sm"
            className="rounded-xl"
            onClick={() => setTimePeriod("monthly")}
          >
            This Month
          </Button>
          <Button
            variant={timePeriod === "all-time" ? "default" : "ghost"}
            size="sm"
            className="rounded-xl"
            onClick={() => setTimePeriod("all-time")}
          >
            All Time
          </Button>
        </div>

        <div className="flex items-center gap-1 p-1 bg-zinc-100 dark:bg-zinc-900 rounded-2xl border border-zinc-200 dark:border-zinc-800">
          <Button
            variant={category === "xp" ? "default" : "ghost"}
            size="sm"
            className="rounded-xl"
            onClick={() => setCategory("xp")}
          >
            <Star className="size-4 mr-2" />
            XP
          </Button>
          <Button
            variant={category === "streak" ? "default" : "ghost"}
            size="sm"
            className="rounded-xl"
            onClick={() => setCategory("streak")}
          >
            <Flame className="size-4 mr-2" />
            Streak
          </Button>
          <Button
            variant={category === "chapters" ? "default" : "ghost"}
            size="sm"
            className="rounded-xl"
            onClick={() => setCategory("chapters")}
          >
            <BookOpen className="size-4 mr-2" />
            Chapters
          </Button>
        </div>
      </div>

      {loading ? (
        <LeaderboardSkeleton />
      ) : users.length >= 3 ? (
        <>
          <div className="grid grid-cols-3 gap-4 items-end pt-12 pb-8">
            <div className="flex flex-col items-center space-y-4">
              <Link href={`/users/${users[1].username}`} className="group">
                <div className="relative">
                  <div className="size-20 md:size-24 rounded-3xl bg-zinc-100 dark:bg-zinc-800 border-2 border-zinc-200 dark:border-zinc-700 flex items-center justify-center overflow-hidden group-hover:scale-105 transition-transform">
                    {users[1].avatar_url ? (
                      <img src={users[1].avatar_url} className="h-full w-full object-cover" alt="" />
                    ) : (
                      <span className="text-2xl font-bold text-zinc-400 uppercase">{users[1].username[0]}</span>
                    )}
                  </div>
                  <div className="absolute -top-3 -right-3 size-8 rounded-full bg-zinc-300 dark:bg-zinc-600 flex items-center justify-center border-4 border-white dark:border-zinc-950">
                    <Medal className="size-4 text-white" />
                  </div>
                </div>
              </Link>
              <div className="text-center">
                <p className="font-bold text-sm truncate max-w-[100px]">{users[1].username}</p>
                <p className="text-xs text-zinc-500">{getCategoryValue(users[1])}</p>
              </div>
              <div className="w-full h-24 bg-zinc-100 dark:bg-zinc-900 rounded-t-2xl border-x border-t border-zinc-200 dark:border-zinc-800 flex items-center justify-center font-black text-2xl text-zinc-300">2</div>
            </div>

            <div className="flex flex-col items-center space-y-4">
              <Link href={`/users/${users[0].username}`} className="group">
                <div className="relative">
                  <div className="size-24 md:size-32 rounded-3xl bg-zinc-900 dark:bg-zinc-50 border-4 border-white dark:border-zinc-950 shadow-2xl flex items-center justify-center overflow-hidden group-hover:scale-105 transition-transform">
                    {users[0].avatar_url ? (
                      <img src={users[0].avatar_url} className="h-full w-full object-cover" alt="" />
                    ) : (
                      <span className="text-4xl font-black text-zinc-500 dark:text-zinc-400 uppercase">{users[0].username[0]}</span>
                    )}
                  </div>
                  <div className="absolute -top-4 -right-4 size-10 rounded-full bg-yellow-500 flex items-center justify-center border-4 border-white dark:border-zinc-950">
                    <Crown className="size-5 text-white fill-white" />
                  </div>
                </div>
              </Link>
              <div className="text-center">
                <p className="font-bold text-lg truncate max-w-[120px]">{users[0].username}</p>
                <p className="text-xs font-bold text-yellow-600 uppercase tracking-widest">{getCategoryValue(users[0])}</p>
              </div>
              <div className="w-full h-32 bg-zinc-900 dark:bg-zinc-50 rounded-t-2xl flex items-center justify-center font-black text-4xl text-white dark:text-zinc-900 shadow-xl">1</div>
            </div>

            <div className="flex flex-col items-center space-y-4">
              <Link href={`/users/${users[2].username}`} className="group">
                <div className="relative">
                  <div className="size-20 md:size-24 rounded-3xl bg-zinc-100 dark:bg-zinc-800 border-2 border-zinc-200 dark:border-zinc-700 flex items-center justify-center overflow-hidden group-hover:scale-105 transition-transform">
                    {users[2].avatar_url ? (
                      <img src={users[2].avatar_url} className="h-full w-full object-cover" alt="" />
                    ) : (
                      <span className="text-2xl font-bold text-zinc-400 uppercase">{users[2].username[0]}</span>
                    )}
                  </div>
                  <div className="absolute -top-3 -right-3 size-8 rounded-full bg-orange-400 dark:bg-orange-700 flex items-center justify-center border-4 border-white dark:border-zinc-950">
                    <Medal className="size-4 text-white" />
                  </div>
                </div>
              </Link>
              <div className="text-center">
                <p className="font-bold text-sm truncate max-w-[100px]">{users[2].username}</p>
                <p className="text-xs text-zinc-500">{getCategoryValue(users[2])}</p>
              </div>
              <div className="w-full h-20 bg-zinc-100 dark:bg-zinc-900 rounded-t-2xl border-x border-t border-zinc-200 dark:border-zinc-800 flex items-center justify-center font-black text-2xl text-zinc-300">3</div>
            </div>
          </div>

          <div className="bg-zinc-50 dark:bg-zinc-900/50 rounded-3xl border border-zinc-100 dark:border-zinc-800 overflow-hidden">
            <div className="p-4 border-b border-zinc-100 dark:border-zinc-800 bg-white/50 dark:bg-zinc-950/50 grid grid-cols-12 gap-4 text-[10px] font-bold uppercase tracking-widest text-zinc-500">
              <div className="col-span-1 text-center">Rank</div>
              <div className="col-span-7 pl-4">User</div>
              <div className="col-span-2 text-right">Level</div>
              <div className="col-span-2 text-right pr-4">{getCategoryLabel()}</div>
            </div>
            <div className="divide-y divide-zinc-100 dark:divide-zinc-800">
              {users.slice(3).map((user, i) => (
                <Link 
                  key={user.username} 
                  href={`/users/${user.username}`}
                  className="p-4 grid grid-cols-12 gap-4 items-center hover:bg-white dark:hover:bg-zinc-950 transition-colors"
                >
                  <div className="col-span-1 text-center font-bold text-zinc-400">{i + 4}</div>
                  <div className="col-span-7 flex items-center gap-3 pl-4">
                    <div className="size-8 rounded-lg bg-zinc-200 dark:bg-zinc-800 flex items-center justify-center text-xs font-bold text-zinc-500 uppercase overflow-hidden">
                      {user.avatar_url ? (
                        <img src={user.avatar_url} className="h-full w-full object-cover" alt="" />
                      ) : (
                        user.username[0]
                      )}
                    </div>
                    <span className="font-bold text-sm">{user.username}</span>
                  </div>
                  <div className="col-span-2 text-right font-medium text-sm">{user.level || 1}</div>
                  <div className="col-span-2 text-right pr-4 font-black text-sm text-blue-500">{getCategoryValue(user)}</div>
                </Link>
              ))}
            </div>
          </div>
        </>
      ) : users.length > 0 ? (
        <div className="bg-zinc-50 dark:bg-zinc-900/50 rounded-3xl border border-zinc-100 dark:border-zinc-800 overflow-hidden">
          <div className="divide-y divide-zinc-100 dark:divide-zinc-800">
            {users.map((user, i) => (
              <Link 
                key={user.username} 
                href={`/users/${user.username}`}
                className="p-4 flex items-center gap-4 hover:bg-white dark:hover:bg-zinc-950 transition-colors"
              >
                <div className="text-center font-bold text-zinc-400 w-8">{i + 1}</div>
                <div className="size-10 rounded-lg bg-zinc-200 dark:bg-zinc-800 flex items-center justify-center overflow-hidden">
                  {user.avatar_url ? (
                    <img src={user.avatar_url} className="h-full w-full object-cover" alt="" />
                  ) : (
                    <span className="font-bold text-zinc-500">{user.username[0]}</span>
                  )}
                </div>
                <div className="flex-1">
                  <p className="font-bold text-sm">{user.username}</p>
                  <p className="text-xs text-zinc-500">Level {user.level || 1}</p>
                </div>
                <div className="font-black text-blue-500">{getCategoryValue(user)}</div>
              </Link>
            ))}
          </div>
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-24 text-center space-y-4">
          <div className="size-20 rounded-full bg-zinc-50 dark:bg-zinc-900 flex items-center justify-center text-zinc-300">
            <Trophy className="size-10" />
          </div>
          <div className="space-y-2">
            <h3 className="text-xl font-bold">No data yet</h3>
            <p className="text-zinc-500 dark:text-zinc-400 max-w-xs mx-auto">
              Start reading and earning XP to appear on the leaderboard!
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
