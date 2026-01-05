"use client"

import { useState, useEffect, useCallback } from "react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Check, Loader2, ExternalLink, ChevronDown, ChevronUp, Filter } from "lucide-react"
import { updateProgress } from "@/lib/actions/library"
import { SyncOutbox } from "@/lib/sync/outbox"
import { toast } from "sonner"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

import { selectBestSource } from "@/lib/source-utils"

interface ChapterSource {
  id: string
  source_name: string
  source_id: string
  chapter_url: string
  published_at: string | null
  discovered_at: string
  is_available?: boolean
  trust_score?: number
}

interface LogicalChapter {
  chapter_number: number
  chapter_title: string | null
  volume_number: number | null
  sources: ChapterSource[]
  is_read: boolean
  latest_upload: string | null
}

interface SeriesSource {
  id: string
  source_name: string
  source_url: string
  chapter_count: number
  trust_score: number
}

interface EnhancedChapterListProps {
  seriesId: string
  libraryEntry: {
    id: string
    last_read_chapter: number | null
    preferred_source: string | null
  } | null
  sources: SeriesSource[]
  userDefaultSource?: string | null
}

export function EnhancedChapterList({ 
  seriesId, 
  libraryEntry,
  sources,
  userDefaultSource,
}: EnhancedChapterListProps) {
  const [chapters, setChapters] = useState<LogicalChapter[]>([])
  const [loading, setLoading] = useState(true)
  const [loadingId, setLoadingId] = useState<string | null>(null)
  const [expandedChapter, setExpandedChapter] = useState<number | null>(null)
  const [sourceFilter, setSourceFilter] = useState<string>("all")
  const [sortBy, setSortBy] = useState<string>("chapter_desc")
  const [showSourceDialog, setShowSourceDialog] = useState(false)
  const [selectedChapter, setSelectedChapter] = useState<LogicalChapter | null>(null)
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [totalChapters, setTotalChapters] = useState(0)

  const preferredSource = libraryEntry?.preferred_source || userDefaultSource

  const fetchChapters = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        limit: "30",
        sort: sortBy,
        grouped: "true",
      })
      if (sourceFilter !== "all") {
        params.set("source", sourceFilter)
      }
      
      const res = await fetch(`/api/series/${seriesId}/chapters?${params}`)
      if (res.ok) {
        const data = await res.json()
        setChapters(data.chapters || [])
        setTotalPages(data.total_pages || 1)
        setTotalChapters(data.total || 0)
      }
    } catch (error) {
      console.error("Failed to fetch chapters:", error)
    } finally {
      setLoading(false)
    }
  }, [seriesId, page, sortBy, sourceFilter])

  useEffect(() => {
    fetchChapters()
  }, [fetchChapters])

  // Opens the chapter URL in a new tab - DOES NOT mark as read
  const openChapter = (source: ChapterSource) => {
    window.open(source.chapter_url, "_blank", "noopener,noreferrer")
  }

  // Handles clicking on a chapter row - Selects best source and navigates
  const handleChapterClick = (chapter: LogicalChapter) => {
    const { source, reason, isFallback } = selectBestSource(
      chapter.sources,
      sources,
      {
        preferredSourceSeries: libraryEntry?.preferred_source,
        preferredSourceGlobal: userDefaultSource
      }
    )

    if (source) {
      if (isFallback) {
        toast.info(`Using fallback source: ${source.source_name}`, {
          description: `Your preferred source is currently unavailable for this chapter.`,
        })
      }
      openChapter(source)
    } else {
      toast.error("No available sources found for this chapter.")
    }
  }

  // Marks a chapter as read - DOES NOT open the source page
  const handleMarkRead = async (chapter: LogicalChapter, e: React.MouseEvent) => {
    e.stopPropagation()
    
    if (!libraryEntry) {
      toast.error("Add to library first to track progress")
      return
    }

    // Already read - no action needed
    if (chapter.is_read) {
      return
    }

    // Resolve best source for telemetry
    const { source } = selectBestSource(
      chapter.sources,
      sources,
      {
        preferredSourceSeries: libraryEntry?.preferred_source,
        preferredSourceGlobal: userDefaultSource
      }
    )
    
    const sourceId = source?.id || chapter.sources[0]?.id
    if (sourceId) {
      setLoadingId(sourceId)
    }
    
    try {
      // Offline support: If offline, enqueue and show optimistic success
      if (!navigator.onLine) {
        SyncOutbox.enqueue('CHAPTER_READ', {
          entryId: libraryEntry.id,
          chapterNumber: chapter.chapter_number,
          sourceId: sourceId
        });
        
        toast.success(`Chapter ${chapter.chapter_number} queued for sync (Offline)`)
        setChapters(prev => prev.map(c => 
          c.chapter_number === chapter.chapter_number 
            ? { ...c, is_read: true }
            : c
        ))
        return
      }

      const result = await updateProgress(libraryEntry.id, chapter.chapter_number, seriesId, sourceId)
      if (result.error) {
        toast.error(result.error)
      } else {
        toast.success(`Marked chapter ${chapter.chapter_number} as read (+${result.xp_gained} XP)`)
        setChapters(prev => prev.map(c => 
          c.chapter_number === chapter.chapter_number 
            ? { ...c, is_read: true }
            : c
        ))
      }
    } catch {
      // Even if network fails unexpectedly, we can fallback to outbox
      SyncOutbox.enqueue('CHAPTER_READ', {
        entryId: libraryEntry.id,
        chapterNumber: chapter.chapter_number,
        sourceId: sourceId
      });
      toast.info(`Connection lost. Chapter ${chapter.chapter_number} will sync when online.`)
      setChapters(prev => prev.map(c => 
        c.chapter_number === chapter.chapter_number 
          ? { ...c, is_read: true }
          : c
      ))
    } finally {
      setLoadingId(null)
    }
  }

  // Opens a specific source from expanded list or dialog - DOES NOT mark as read
  const handleSourceClick = (source: ChapterSource, e: React.MouseEvent) => {
    e.stopPropagation()
    openChapter(source)
  }

  // Opens source from dialog - DOES NOT mark as read
  const handleDialogSourceClick = (source: ChapterSource) => {
    openChapter(source)
    setShowSourceDialog(false)
  }

  const formatDate = (dateString: string | null) => {
    if (!dateString) return "Unknown"
    const date = new Date(dateString)
    const now = new Date()
    const diffDays = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24))
    
    if (diffDays === 0) return "Today"
    if (diffDays === 1) return "Yesterday"
    if (diffDays < 7) return `${diffDays} days ago`
    if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`
    return date.toLocaleDateString()
  }

  const getSourceIcon = (sourceName: string) => {
    const name = sourceName.toLowerCase()
    if (name.includes("mangadex")) return "MD"
    if (name.includes("mangapark")) return "MP"
    if (name.includes("mangasee")) return "MS"
    return sourceName.slice(0, 2).toUpperCase()
  }

  const getSourceColor = (sourceName: string) => {
    const name = sourceName.toLowerCase()
    if (name.includes("mangadex")) return "bg-orange-500"
    if (name.includes("mangapark")) return "bg-green-500"
    if (name.includes("mangasee")) return "bg-blue-500"
    return "bg-zinc-500"
  }

  if (loading && chapters.length === 0) {
    return (
      <div className="space-y-2">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="animate-pulse flex items-center justify-between p-4 rounded-xl border border-zinc-100 dark:border-zinc-900">
            <div className="flex items-center gap-4">
              <div className="size-10 rounded-lg bg-zinc-200 dark:bg-zinc-800" />
              <div className="space-y-2">
                <div className="h-4 w-24 bg-zinc-200 dark:bg-zinc-800 rounded" />
                <div className="h-3 w-16 bg-zinc-100 dark:bg-zinc-900 rounded" />
              </div>
            </div>
            <div className="h-8 w-24 bg-zinc-200 dark:bg-zinc-800 rounded-full" />
          </div>
        ))}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-2">
          <span className="text-sm text-zinc-500">{totalChapters} chapters</span>
        </div>
        <div className="flex items-center gap-2">
          {sources.length > 1 && (
            <Select value={sourceFilter} onValueChange={setSourceFilter}>
              <SelectTrigger className="w-[140px] h-9 text-sm">
                <Filter className="size-3.5 mr-2" />
                <SelectValue placeholder="All Sources" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Sources</SelectItem>
                {sources.map(source => (
                  <SelectItem key={source.id} value={source.source_name}>
                    {source.source_name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          <Select value={sortBy} onValueChange={setSortBy}>
            <SelectTrigger className="w-[130px] h-9 text-sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="chapter_desc">Newest First</SelectItem>
              <SelectItem value="chapter_asc">Oldest First</SelectItem>
              <SelectItem value="discovered_desc">Recently Added</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {chapters.length === 0 ? (
        <div className="text-center py-12 text-zinc-500">
          <p>No chapters available yet</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-1.5">
          {chapters.map((chapter) => {
            const isExpanded = expandedChapter === chapter.chapter_number
            const hasMultipleSources = chapter.sources.length > 1

            return (
              <div key={chapter.chapter_number} className="group">
                <div 
                  className={`flex items-center justify-between p-3 rounded-xl border transition-all cursor-pointer ${
                    chapter.is_read 
                      ? 'bg-zinc-50 dark:bg-zinc-900/50 border-zinc-100 dark:border-zinc-800 opacity-60' 
                      : 'border-zinc-100 dark:border-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-900'
                  }`}
                  onClick={() => handleChapterClick(chapter)}
                >
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <div className={`size-9 rounded-lg flex items-center justify-center text-xs font-bold shrink-0 transition-colors ${
                      chapter.is_read 
                        ? 'bg-zinc-200 dark:bg-zinc-800 text-zinc-500' 
                        : 'bg-zinc-100 dark:bg-zinc-800 group-hover:bg-zinc-900 group-hover:text-zinc-50 dark:group-hover:bg-zinc-50 dark:group-hover:text-zinc-900'
                    }`}>
                      {chapter.chapter_number}
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className={`font-semibold text-sm truncate ${chapter.is_read ? 'text-zinc-500' : ''}`}>
                        Chapter {chapter.chapter_number}
                        {chapter.chapter_title && (
                          <span className="font-normal text-zinc-500 ml-1.5">
                            {chapter.chapter_title}
                          </span>
                        )}
                      </p>
                      <div className="flex items-center gap-2 text-xs text-zinc-500">
                        <span>{formatDate(chapter.latest_upload)}</span>
                        {hasMultipleSources && (
                          <Badge variant="secondary" className="text-[10px] px-1.5 py-0 h-4">
                            {chapter.sources.length} sources
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0 ml-2">
                    <div className="flex -space-x-1">
                      {chapter.sources.slice(0, 3).map((source, i) => (
                        <div
                          key={source.id}
                          className={`size-5 rounded-full ${getSourceColor(source.source_name)} text-white text-[8px] font-bold flex items-center justify-center border-2 border-white dark:border-zinc-950`}
                          style={{ zIndex: 3 - i }}
                          title={source.source_name}
                        >
                          {getSourceIcon(source.source_name)}
                        </div>
                      ))}
                      {chapter.sources.length > 3 && (
                        <div className="size-5 rounded-full bg-zinc-300 dark:bg-zinc-700 text-zinc-600 dark:text-zinc-300 text-[8px] font-bold flex items-center justify-center border-2 border-white dark:border-zinc-950">
                          +{chapter.sources.length - 3}
                        </div>
                      )}
                    </div>

                    {hasMultipleSources && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="size-7 p-0"
                        onClick={(e) => {
                          e.stopPropagation()
                          setExpandedChapter(isExpanded ? null : chapter.chapter_number)
                        }}
                      >
                        {isExpanded ? <ChevronUp className="size-3.5" /> : <ChevronDown className="size-3.5" />}
                      </Button>
                    )}

                    <Button 
                      variant={chapter.is_read ? "ghost" : "outline"} 
                      size="sm" 
                      className={`h-7 text-xs font-bold rounded-full px-2.5 ${
                        chapter.is_read ? 'text-green-500' : 'border-zinc-200 dark:border-zinc-800'
                      }`}
                      onClick={(e) => handleMarkRead(chapter, e)}
                      disabled={loadingId === chapter.sources[0]?.id || chapter.is_read}
                    >
                      {loadingId === chapter.sources[0]?.id ? (
                        <Loader2 className="size-3 animate-spin" />
                      ) : chapter.is_read ? (
                        <>
                          <Check className="size-3 mr-1" />
                          READ
                        </>
                      ) : (
                        "MARK READ"
                      )}
                    </Button>
                  </div>
                </div>

                {isExpanded && hasMultipleSources && (
                  <div className="ml-12 mt-1 space-y-1 animate-in slide-in-from-top-2 duration-200">
                    {chapter.sources.map((source) => (
                      <div
                        key={source.id}
                        className="flex items-center justify-between p-2.5 rounded-lg bg-zinc-50 dark:bg-zinc-900/50 border border-zinc-100 dark:border-zinc-800 cursor-pointer hover:bg-zinc-100 dark:hover:bg-zinc-800/50 transition-colors"
                        onClick={(e) => handleSourceClick(source, e)}
                      >
                          <div className="flex items-center gap-2">
                            <div className={`size-6 rounded-md ${getSourceColor(source.source_name)} text-white text-[9px] font-bold flex items-center justify-center`}>
                              {getSourceIcon(source.source_name)}
                            </div>
                            <div>
                              <p className="text-xs font-medium capitalize">{source.source_name}</p>
                              <div className="flex items-center gap-1.5 text-[10px] text-zinc-500">
                                <span>{formatDate(source.published_at)}</span>
                              </div>
                            </div>
                          </div>
                        <ExternalLink className="size-3.5 text-zinc-400" />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2 pt-4">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1 || loading}
          >
            Previous
          </Button>
          <span className="text-sm text-zinc-500">
            Page {page} of {totalPages}
          </span>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages || loading}
          >
            Next
          </Button>
        </div>
      )}

      <Dialog open={showSourceDialog} onOpenChange={setShowSourceDialog}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              Select Source - Chapter {selectedChapter?.chapter_number}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-2 mt-4">
            {selectedChapter?.sources.map((source) => (
              <div
                key={source.id}
                className="flex items-center justify-between p-3 rounded-lg border border-zinc-200 dark:border-zinc-800 cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-900 transition-colors"
                onClick={() => handleDialogSourceClick(source)}
              >
                  <div className="flex items-center gap-3">
                    <div className={`size-8 rounded-lg ${getSourceColor(source.source_name)} text-white text-xs font-bold flex items-center justify-center`}>
                      {getSourceIcon(source.source_name)}
                    </div>
                    <div>
                      <p className="font-medium capitalize">{source.source_name}</p>
                      <div className="flex items-center gap-2 text-xs text-zinc-500">
                        <span>{formatDate(source.published_at)}</span>
                      </div>
                    </div>
                  </div>
                <ExternalLink className="size-4 text-zinc-400" />
              </div>
            ))}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
