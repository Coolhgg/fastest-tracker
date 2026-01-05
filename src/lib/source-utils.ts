export interface ChapterSource {
  id: string
  source_name: string
  source_id: string
  chapter_url: string
  published_at: string | null
  discovered_at: string
  is_available?: boolean
  trust_score?: number
}

export interface SeriesSourcePreference {
  id: string
  source_name: string
  trust_score: number
}

export interface SourceSelectionResult {
  source: ChapterSource | null
  reason: 'preferred_series' | 'preferred_global' | 'trust_score' | 'discovered_at' | 'none'
  isFallback: boolean
}

/**
 * Selects the best available source for a chapter based on user preferences and source quality.
 * 
 * Logic:
 * 1. Series-Specific Preference (if exists and available)
 * 2. Global User Preference (if exists and available)
 * 3. Trust-Based Default (Trust score DESC, then discovered_at DESC)
 */
export function selectBestSource(
  sources: ChapterSource[],
  seriesSources: SeriesSourcePreference[],
  preferences: {
    preferredSourceSeries?: string | null
    preferredSourceGlobal?: string | null
  }
): SourceSelectionResult {
  if (!sources || sources.length === 0) {
    return { source: null, reason: 'none', isFallback: false }
  }

  // Filter for available sources only
  const availableSources = sources.filter(s => s.is_available !== false)
  if (availableSources.length === 0) {
    return { source: null, reason: 'none', isFallback: false }
  }

  // 1. Check Per-Series Preference
  if (preferences.preferredSourceSeries) {
    const match = availableSources.find(s => s.source_name === preferences.preferredSourceSeries)
    if (match) {
      return { source: match, reason: 'preferred_series', isFallback: false }
    }
  }

  // 2. Check Global Preference
  if (preferences.preferredSourceGlobal) {
    const match = availableSources.find(s => s.source_name === preferences.preferredSourceGlobal)
    if (match) {
      return { 
        source: match, 
        reason: 'preferred_global', 
        isFallback: !!preferences.preferredSourceSeries 
      }
    }
  }

  // 3. Fallback to Trust-Based Default
  const sortedSources = [...availableSources].sort((a, b) => {
    // Priority 1: Trust Score
    const trustA = a.trust_score ?? seriesSources.find(ss => ss.source_name === a.source_name)?.trust_score ?? 0
    const trustB = b.trust_score ?? seriesSources.find(ss => ss.source_name === b.source_name)?.trust_score ?? 0
    
    if (trustB !== trustA) {
      return trustB - trustA
    }
    
    // Priority 2: Discovered Date
    const dateA = new Date(a.discovered_at).getTime()
    const dateB = new Date(b.discovered_at).getTime()
    return dateB - dateA
  })

  const bestMatch = sortedSources[0]
  
  return {
    source: bestMatch,
    reason: 'trust_score',
    isFallback: !!(preferences.preferredSourceSeries || preferences.preferredSourceGlobal)
  }
}
