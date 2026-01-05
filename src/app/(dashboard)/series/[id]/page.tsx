import { createClient } from "@/lib/supabase/server"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Star, Users, Calendar, Share2, MoreHorizontal, ExternalLink, Globe, User } from "lucide-react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { SeriesActions } from "@/components/series/series-actions"
import { EnhancedChapterList } from "@/components/series/enhanced-chapter-list"
import { SeriesStatsTab } from "@/components/series/series-stats-tab"
import { notFound } from "next/navigation"
import { selectBestCover } from "@/lib/cover-resolver"
import { SeriesDetailCover } from "@/components/series/series-detail-cover"
import { ExternalLinkButton, SourceCard } from "@/components/series/external-link-button"
import Link from "next/link"

interface ExternalLink {
  site: string
  url: string
}

export default async function SeriesDetailPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()

  const { data: series, error: seriesError } = await supabase
    .from('series')
    .select(`
      *,
      series_sources(*)
    `)
    .eq('id', id)
    .single()

  if (seriesError || !series) {
    console.error("Series fetch error:", seriesError)
    notFound()
  }

  let seriesCreators: { role: string; creators: { id: string; name: string } | null }[] = []
  try {
    const { data: creatorsData } = await supabase
      .from('series_creators')
      .select('role, creators(id, name)')
      .eq('series_id', id)
    seriesCreators = (creatorsData || []) as typeof seriesCreators
  } catch (err) {
    console.error("Failed to fetch creators:", err)
  }

  const bestCover = selectBestCover(series.series_sources || [])
  const coverUrl = bestCover?.cover_url || series.cover_url

  let libraryEntry = null
  let userSettings = null
  if (user) {
    const [libraryRes, userRes] = await Promise.all([
      supabase
        .from('library_entries')
        .select('*')
        .eq('series_id', id)
        .eq('user_id', user.id)
        .single(),
      supabase
        .from('users')
        .select('default_source')
        .eq('id', user.id)
        .single()
    ])
    libraryEntry = libraryRes.data
    userSettings = userRes.data
  }

  const { count: chapterCount } = await supabase
    .from('chapters')
    .select('*', { count: 'exact', head: true })
    .eq('series_id', id)

  const authors = seriesCreators
    .filter((sc) => sc.role === 'author' && sc.creators)
    .map((sc) => sc.creators!)
  const artists = seriesCreators
    .filter((sc) => sc.role === 'artist' && sc.creators)
    .map((sc) => sc.creators!)

  const year = series.year || series.release_year || (series.created_at ? new Date(series.created_at).getFullYear() : null)
  
  const altTitles = Array.isArray(series.alternative_titles) 
    ? series.alternative_titles as string[]
    : []

  const externalLinks = (series.external_links as ExternalLink[] | null) || []

  const sourcesForChapterList = (series.series_sources || []).map((s: {
    id: string
    source_name: string
    source_url: string
    source_chapter_count: number | null
    trust_score: number
  }) => ({
    id: s.id,
    source_name: s.source_name,
    source_url: s.source_url,
    chapter_count: s.source_chapter_count || 0,
    trust_score: Number(s.trust_score),
  }))

  const getSourceColor = (sourceName: string) => {
    const name = sourceName.toLowerCase()
    if (name.includes("mangadex")) return "bg-orange-500"
    if (name.includes("mangapark")) return "bg-green-500"
    if (name.includes("mangasee")) return "bg-blue-500"
    return "bg-zinc-500"
  }

  const getSourceIcon = (sourceName: string) => {
    const name = sourceName.toLowerCase()
    if (name.includes("mangadex")) return "MD"
    if (name.includes("mangapark")) return "MP"
    if (name.includes("mangasee")) return "MS"
    return sourceName.slice(0, 2).toUpperCase()
  }

  return (
    <div className="flex flex-col min-h-full bg-white dark:bg-zinc-950">
      <div className="relative h-[250px] md:h-[350px] w-full">
        <div className="absolute inset-0 bg-gradient-to-t from-white via-white/50 to-transparent dark:from-zinc-950 dark:via-zinc-950/50 z-10" />
        {coverUrl && (
          <SeriesDetailCover
            coverUrl={coverUrl}
            title={series.title}
            contentRating={series.content_rating}
            variant="background"
          />
        )}
        
        <div className="absolute bottom-0 left-0 right-0 p-6 md:p-12 z-20 max-w-7xl mx-auto w-full flex flex-col md:flex-row items-end gap-8">
          <div className="hidden md:block w-[200px] shrink-0 aspect-[3/4] rounded-2xl overflow-hidden border-4 border-white dark:border-zinc-950 shadow-2xl shadow-zinc-500/20">
            <SeriesDetailCover
              coverUrl={coverUrl}
              title={series.title}
              contentRating={series.content_rating}
              variant="main"
            />
          </div>
          <div className="flex-1 space-y-4 pb-4">
            <div className="flex flex-wrap gap-2">
              <Badge variant="secondary" className="bg-zinc-100 text-zinc-900 dark:bg-zinc-800 dark:text-zinc-50 capitalize">{series.type}</Badge>
              <Badge variant="secondary" className="bg-zinc-100 text-zinc-900 dark:bg-zinc-800 dark:text-zinc-50 capitalize">{series.status}</Badge>
              {series.demographic && (
                <Badge variant="secondary" className="bg-zinc-100 text-zinc-900 dark:bg-zinc-800 dark:text-zinc-50 capitalize">{series.demographic}</Badge>
              )}
              {chapterCount && chapterCount > 0 && (
                <Badge variant="secondary" className="bg-zinc-100 text-zinc-900 dark:bg-zinc-800 dark:text-zinc-50">
                  {chapterCount} Chapters
                </Badge>
              )}
              {series.content_rating && series.content_rating !== 'safe' && (
                <Badge variant="secondary" className="bg-red-100 text-red-900 dark:bg-red-900/30 dark:text-red-400 capitalize">
                  {series.content_rating}
                </Badge>
              )}
            </div>
            <h1 className="text-3xl md:text-5xl font-extrabold tracking-tight text-zinc-900 dark:text-zinc-50 leading-tight">
              {series.title}
            </h1>
            {altTitles.length > 0 && (
              <p className="text-sm text-zinc-500 truncate max-w-xl">
                {altTitles[0]}
              </p>
            )}
            <div className="flex items-center gap-6 text-sm font-medium text-zinc-500 dark:text-zinc-400">
              <span className="flex items-center gap-1.5"><Star className="size-4 text-yellow-500 fill-yellow-500" /> {series.average_rating || "N/A"}</span>
              <span className="flex items-center gap-1.5"><Users className="size-4" /> {series.total_follows ? `${(series.total_follows / 1000).toFixed(1)}K` : "0"} Followers</span>
              {year && <span className="flex items-center gap-1.5"><Calendar className="size-4" /> {year}</span>}
              {series.original_language && (
                <span className="flex items-center gap-1.5">
                  <Globe className="size-4" /> 
                  {series.original_language.toUpperCase()}
                </span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-3 pb-4">
            <SeriesActions seriesId={series.id} libraryEntry={libraryEntry} />
            <Button variant="outline" size="icon" className="rounded-full border-zinc-200 dark:border-zinc-800">
              <Share2 className="size-4" />
            </Button>
            <Button variant="outline" size="icon" className="rounded-full border-zinc-200 dark:border-zinc-800">
              <MoreHorizontal className="size-4" />
            </Button>
          </div>
        </div>
      </div>

      <div className="p-6 md:p-12 max-w-7xl mx-auto w-full grid grid-cols-1 lg:grid-cols-3 gap-12">
        <div className="lg:col-span-2 space-y-12">
          <Tabs defaultValue="chapters" className="w-full">
            <TabsList className="bg-transparent border-b border-zinc-100 dark:border-zinc-900 w-full justify-start rounded-none h-auto p-0 gap-8">
              <TabsTrigger value="chapters" className="rounded-none border-b-2 border-transparent data-[state=active]:border-zinc-900 dark:data-[state=active]:border-zinc-50 px-0 pb-4 font-bold text-lg">Chapters</TabsTrigger>
              <TabsTrigger value="overview" className="rounded-none border-b-2 border-transparent data-[state=active]:border-zinc-900 dark:data-[state=active]:border-zinc-50 px-0 pb-4 font-bold text-lg">Overview</TabsTrigger>
              <TabsTrigger value="statistics" className="rounded-none border-b-2 border-transparent data-[state=active]:border-zinc-900 dark:data-[state=active]:border-zinc-50 px-0 pb-4 font-bold text-lg">Statistics</TabsTrigger>
            </TabsList>
            
            <TabsContent value="chapters" className="pt-8 space-y-6">
              <EnhancedChapterList 
                seriesId={series.id} 
                libraryEntry={libraryEntry ? {
                  id: libraryEntry.id,
                  last_read_chapter: libraryEntry.last_read_chapter ? Number(libraryEntry.last_read_chapter) : null,
                  preferred_source: libraryEntry.preferred_source,
                } : null}
                sources={sourcesForChapterList}
                userDefaultSource={userSettings?.default_source}
              />
            </TabsContent>

            <TabsContent value="overview" className="pt-8 space-y-8">
              <div className="space-y-4">
                <h3 className="text-xl font-bold">Synopsis</h3>
                <p className="text-zinc-600 dark:text-zinc-400 leading-relaxed max-w-2xl whitespace-pre-line">
                  {series.description || "No description available."}
                </p>
              </div>

              {(authors.length > 0 || artists.length > 0) && (
                <div className="space-y-4">
                  <h3 className="text-xl font-bold">Creators</h3>
                  <div className="flex flex-wrap gap-4">
                    {authors.map((author: { id: string; name: string }) => (
                      <div key={author.id} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-zinc-100 dark:bg-zinc-900">
                        <User className="size-4 text-zinc-500" />
                        <div>
                          <p className="text-sm font-medium">{author.name}</p>
                          <p className="text-xs text-zinc-500">Author</p>
                        </div>
                      </div>
                    ))}
                    {artists.filter((a: { id: string }) => !authors.find((au: { id: string }) => au.id === a.id)).map((artist: { id: string; name: string }) => (
                      <div key={artist.id} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-zinc-100 dark:bg-zinc-900">
                        <User className="size-4 text-zinc-500" />
                        <div>
                          <p className="text-sm font-medium">{artist.name}</p>
                          <p className="text-xs text-zinc-500">Artist</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {series.genres && series.genres.length > 0 && (
                <div className="space-y-4">
                  <h3 className="text-xl font-bold">Genres</h3>
                  <div className="flex flex-wrap gap-2">
                    {series.genres.map((genre: string) => (
                      <Badge key={genre} variant="outline" className="border-zinc-200 dark:border-zinc-800 capitalize">{genre}</Badge>
                    ))}
                  </div>
                </div>
              )}

              {series.themes && series.themes.length > 0 && (
                <div className="space-y-4">
                  <h3 className="text-xl font-bold">Themes</h3>
                  <div className="flex flex-wrap gap-2">
                    {series.themes.map((theme: string) => (
                      <Badge key={theme} variant="secondary" className="bg-zinc-100 dark:bg-zinc-800 capitalize">{theme}</Badge>
                    ))}
                  </div>
                </div>
              )}

              {series.tags && series.tags.length > 0 && (
                <div className="space-y-4">
                  <h3 className="text-xl font-bold">Tags</h3>
                  <div className="flex flex-wrap gap-2">
                    {series.tags.map((tag: string) => (
                      <Badge key={tag} variant="secondary" className="bg-zinc-100 dark:bg-zinc-800">{tag}</Badge>
                    ))}
                  </div>
                </div>
              )}

              {altTitles.length > 0 && (
                <div className="space-y-4">
                  <h3 className="text-xl font-bold">Alternative Titles</h3>
                  <ul className="space-y-1 text-sm text-zinc-600 dark:text-zinc-400">
                    {altTitles.slice(0, 5).map((title, i) => (
                      <li key={i}>{title}</li>
                    ))}
                    {altTitles.length > 5 && (
                      <li className="text-zinc-500">+{altTitles.length - 5} more</li>
                    )}
                  </ul>
                </div>
              )}

              {externalLinks.length > 0 && (
                <div className="space-y-4">
                  <h3 className="text-xl font-bold">External Links</h3>
                  <div className="flex flex-wrap gap-2">
                      {externalLinks.map((link, i) => (
                        <ExternalLinkButton
                          key={i}
                          url={link.url}
                          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-zinc-100 dark:bg-zinc-900 hover:bg-zinc-200 dark:hover:bg-zinc-800 transition-colors text-sm"
                        >
                          <ExternalLink className="size-3.5" />
                          {link.site}
                        </ExternalLinkButton>
                      ))}
                  </div>
                </div>
              )}
            </TabsContent>

            <TabsContent value="statistics">
              <SeriesStatsTab seriesId={series.id} />
            </TabsContent>
          </Tabs>
        </div>

        <div className="space-y-8">
          {series.series_sources && series.series_sources.length > 0 && (
            <div className="bg-zinc-50 dark:bg-zinc-900/50 p-6 rounded-3xl border border-zinc-100 dark:border-zinc-800 space-y-6">
              <h3 className="font-bold">Available Sources</h3>
              <div className="space-y-3">
                  {series.series_sources.map((source: {
                    id: string
                    source_name: string
                    source_url: string
                    source_chapter_count: number | null
                    trust_score: number
                    last_success_at: string | null
                  }) => (
                    <SourceCard 
                      key={source.id} 
                      sourceUrl={source.source_url}
                      className="flex items-center justify-between p-3 rounded-xl bg-white dark:bg-zinc-950 border border-zinc-100 dark:border-zinc-800 cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-900 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <div className={`size-9 rounded-lg ${getSourceColor(source.source_name)} text-white text-xs font-bold flex items-center justify-center`}>
                          {getSourceIcon(source.source_name)}
                        </div>
                        <div>
                          <p className="text-sm font-bold capitalize">{source.source_name}</p>
                          {source.source_chapter_count && (
                            <p className="text-xs text-zinc-500">{source.source_chapter_count} chapters</p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="flex items-center gap-1.5 text-[10px] font-bold text-green-500">
                          <div className="size-1.5 rounded-full bg-green-500" />
                          {Math.round(Number(source.trust_score) * 10)}%
                        </div>
                        <ExternalLink className="size-3.5 text-zinc-400" />
                      </div>
                    </SourceCard>
                  ))}
              </div>
            </div>
          )}

          <div className="bg-zinc-50 dark:bg-zinc-900/50 p-6 rounded-3xl border border-zinc-100 dark:border-zinc-800 space-y-6">
            <h3 className="font-bold">Information</h3>
            <div className="space-y-4 text-sm">
              <div className="flex justify-between">
                <span className="text-zinc-500">Type</span>
                <span className="font-bold capitalize">{series.type}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-500">Status</span>
                <span className="font-bold capitalize">{series.status}</span>
              </div>
              {series.demographic && (
                <div className="flex justify-between">
                  <span className="text-zinc-500">Demographic</span>
                  <span className="font-bold capitalize">{series.demographic}</span>
                </div>
              )}
              <div className="flex justify-between">
                <span className="text-zinc-500">Chapters</span>
                <span className="font-bold">{chapterCount || 0}</span>
              </div>
              {year && (
                <div className="flex justify-between">
                  <span className="text-zinc-500">Year</span>
                  <span className="font-bold">{year}</span>
                </div>
              )}
              {series.original_language && (
                <div className="flex justify-between">
                  <span className="text-zinc-500">Original Language</span>
                  <span className="font-bold uppercase">{series.original_language}</span>
                </div>
              )}
              <div className="flex justify-between">
                <span className="text-zinc-500">Views</span>
                <span className="font-bold">{series.total_views?.toLocaleString() || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-500">Content Rating</span>
                <span className="font-bold capitalize">{series.content_rating || "Safe"}</span>
              </div>
            </div>
          </div>

          {series.translated_languages && series.translated_languages.length > 0 && (
            <div className="bg-zinc-50 dark:bg-zinc-900/50 p-6 rounded-3xl border border-zinc-100 dark:border-zinc-800 space-y-4">
              <h3 className="font-bold">Available Languages</h3>
              <div className="flex flex-wrap gap-2">
                {series.translated_languages.map((lang: string) => (
                  <Badge key={lang} variant="secondary" className="uppercase text-xs">
                    {lang}
                  </Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
