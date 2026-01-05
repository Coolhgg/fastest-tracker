export type SafeBrowsingMode = 'sfw' | 'sfw_plus' | 'nsfw'
export type SafeBrowsingIndicator = 'toggle' | 'icon' | 'hidden'

export const SAFE_BROWSING_MODES: { value: SafeBrowsingMode; label: string; description: string }[] = [
  {
    value: 'sfw',
    label: 'Safe for Work (SFW)',
    description: 'NSFW covers are replaced with a placeholder. Titles remain visible.',
  },
  {
    value: 'sfw_plus',
    label: 'Safe for Work + (Blur NSFW)',
    description: 'NSFW covers are blurred. Click to reveal individually.',
  },
  {
    value: 'nsfw',
    label: 'Not Safe for Work (NSFW)',
    description: 'All covers shown as-is. 18+ badge displayed on mature content.',
  },
]

export const SAFE_BROWSING_INDICATORS: { value: SafeBrowsingIndicator; label: string }[] = [
  { value: 'toggle', label: 'Show NSFW/SFW toggle' },
  { value: 'icon', label: 'Show icon only' },
  { value: 'hidden', label: 'Hide' },
]

export const NSFW_CONTENT_RATINGS = ['erotica', 'pornographic'] as const

export function isNSFW(contentRating: string | null | undefined): boolean {
  if (!contentRating) return false
  return NSFW_CONTENT_RATINGS.includes(contentRating.toLowerCase() as any)
}

export const SAFE_BROWSING_STORAGE_KEY = 'kenmei_safe_browsing_mode'
export const SAFE_BROWSING_INDICATOR_STORAGE_KEY = 'kenmei_safe_browsing_indicator'
