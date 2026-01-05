"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Plus, Check, Bookmark, Loader2 } from "lucide-react"
import { addToLibrary, removeFromLibrary } from "@/lib/actions/library"
import { SyncOutbox } from "@/lib/sync/outbox"
import { toast } from "sonner"

export function SeriesActions({ 
  seriesId, 
  libraryEntry 
}: { 
  seriesId: string, 
  libraryEntry: any 
}) {
  const [loading, setLoading] = useState(false)

  const handleAdd = async () => {
    setLoading(true)
    try {
      if (!navigator.onLine) {
        SyncOutbox.enqueue('LIBRARY_UPDATE', { entryId: seriesId, status: 'reading' });
        toast.success("Series queued to be added (Offline)");
        return;
      }
      const result = await addToLibrary(seriesId)
      if (result.error) {
        toast.error(result.error)
      } else {
        toast.success("Added to library")
      }
    } catch (error) {
      SyncOutbox.enqueue('LIBRARY_UPDATE', { entryId: seriesId, status: 'reading' });
      toast.info("Connection lost. Series will be added when online.");
    } finally {
      setLoading(false)
    }
  }

  const handleRemove = async () => {
    setLoading(true)
    try {
      const result = await removeFromLibrary(libraryEntry.id)
      if (result.error) {
        toast.error(result.error)
      } else {
        toast.success("Removed from library")
      }
    } catch (error) {
      toast.error("Failed to remove from library")
    } finally {
      setLoading(false)
    }
  }

  if (libraryEntry) {
    return (
      <Button 
        variant="outline" 
        className="rounded-full px-6 border-zinc-200 dark:border-zinc-800"
        onClick={handleRemove}
        disabled={loading}
      >
        {loading ? <Loader2 className="size-4 mr-2 animate-spin" /> : <Check className="size-4 mr-2 text-green-500" />}
        In Library
      </Button>
    )
  }

  return (
    <Button 
      className="bg-zinc-900 text-zinc-50 hover:bg-zinc-800 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-zinc-200 rounded-full px-8"
      onClick={handleAdd}
      disabled={loading}
    >
      {loading ? <Loader2 className="size-4 mr-2 animate-spin" /> : <Plus className="size-4 mr-2" />}
      Add to Library
    </Button>
  )
}
