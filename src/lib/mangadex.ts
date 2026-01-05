import { getMangaDexHeaders, MANGADEX_API_BASE } from './config/mangadex';
import { mergeRelationships, mergeRelationshipsSingle } from './utils';
import { isMangaDexPlaceholder } from './cover-resolver';

export { getMangaDexHeaders, MANGADEX_API_BASE } from './config/mangadex';

export const MANGADEX_COVER_BASE = 'https://uploads.mangadex.org/covers';

export interface MangaDexCandidate {
  mangadex_id: string;
  title: string;
  alternative_titles: string[];
  description: string;
  status: string;
  type: string;
  genres: string[];
  content_rating?: string;
  cover_url?: string;
  source: 'mangadex';
}

export function getMangaDexCoverUrl(mangaId: string, fileName: string): string {
  return `${MANGADEX_COVER_BASE}/${mangaId}/${fileName}`;
}

function selectBestCoverFromRelationships(
  relationships: any[],
  mangaId: string
): string | undefined {
  const coverArts = relationships.filter(
    (r: any) => r.type === 'cover_art' && r.attributes?.fileName
  );

  if (coverArts.length === 0) return undefined;

  const validCovers = coverArts
    .map((rel: any) => {
      const fileName = rel.attributes.fileName;
      const url = getMangaDexCoverUrl(mangaId, fileName);
      const volume = rel.attributes.volume;
      const locale = rel.attributes.locale;
      return { url, fileName, volume, locale, rel };
    })
    .filter((c) => !isMangaDexPlaceholder(c.url));

  if (validCovers.length === 0) return undefined;

  // Try to find volume 1 in English if possible, then any volume 1
  const englishVolumeOne = validCovers.find(
    (c) => (c.volume === '1' || c.volume === '01') && c.locale === 'en'
  );
  if (englishVolumeOne) return englishVolumeOne.url;

  const volumeOneCover = validCovers.find(
    (c) => c.volume === '1' || c.volume === '01'
  );
  if (volumeOneCover) return volumeOneCover.url;

  const sortedByVolume = validCovers.sort((a, b) => {
    const volA = parseFloat(a.volume) || Infinity;
    const volB = parseFloat(b.volume) || Infinity;
    return volA - volB;
  });

  return sortedByVolume[0]?.url;
}

export async function getCoversBatch(mangaIds: string[]): Promise<Map<string, string>> {
  if (mangaIds.length === 0) return new Map();

  const url = new URL(`${MANGADEX_API_BASE}/cover`);
  mangaIds.forEach(id => url.searchParams.append('manga[]', id));
  url.searchParams.set('limit', '100'); // Maximum limit

  const response = await fetch(url.toString(), {
    headers: getMangaDexHeaders(),
  });

  if (!response.ok) {
    throw new Error(`MangaDex Cover API error: ${response.status}`);
  }

  const data = await response.json();
  const coverMap = new Map<string, string>();

  // Group covers by manga ID to pick the best one
  const mangaCovers = new Map<string, any[]>();
  for (const cover of data.data) {
    const mangaRel = cover.relationships.find((r: any) => r.type === 'manga');
    if (mangaRel) {
      const existing = mangaCovers.get(mangaRel.id) ?? [];
      existing.push(cover);
      mangaCovers.set(mangaRel.id, existing);
    }
  }

  for (const [mangaId, covers] of mangaCovers.entries()) {
    const bestCover = selectBestCoverFromRelationships(covers, mangaId);
    if (bestCover) {
      coverMap.set(mangaId, bestCover);
    }
  }

  return coverMap;
}

export async function searchMangaDex(searchTerm: string): Promise<MangaDexCandidate[]> {
  const url = new URL(`${MANGADEX_API_BASE}/manga`);
  url.searchParams.set('title', searchTerm);
  url.searchParams.set('limit', '32');

  url.searchParams.append('includes[]', 'cover_art');
  url.searchParams.append('contentRating[]', 'safe');
  url.searchParams.append('contentRating[]', 'suggestive');
  url.searchParams.append('contentRating[]', 'erotica');
  url.searchParams.append('contentRating[]', 'pornographic');

  const response = await fetch(url.toString(), {
    headers: getMangaDexHeaders(),
  });

  if (response.status === 429) {
    throw new Error('MangaDex Rate Limit exceeded');
  }
  if (response.status === 403 || response.headers.get('server')?.includes('cloudflare')) {
    throw new Error('MangaDex blocked by Cloudflare/Forbidden');
  }
  if (!response.ok) {
    throw new Error(`MangaDex API error: ${response.status}`);
  }

  const data = await response.json();
  const mergedResults = mergeRelationships(data.data, data.included || []);
  
  const candidates: MangaDexCandidate[] = [];

  for (const manga of mergedResults) {
    const attrs = manga.attributes;
    const title = attrs.title.en || Object.values(attrs.title)[0] as string;
    const altTitles = attrs.altTitles.map((t: any) => Object.values(t)[0] as string);
    const description = attrs.description.en || Object.values(attrs.description)[0] as string || '';
    
    const coverUrl = selectBestCoverFromRelationships(manga.relationships, manga.id);

    const genres = attrs.tags
      .filter((tag: any) => tag.attributes.group === 'genre')
      .map((tag: any) => tag.attributes.name.en);

    candidates.push({
      mangadex_id: manga.id,
      title,
      alternative_titles: Array.from(new Set(altTitles)),
      description,
      status: attrs.status,
      type: attrs.publicationDemographic || 'unknown',
      genres,
      content_rating: attrs.contentRating,
      cover_url: coverUrl,
      source: 'mangadex',
    });
  }

  return candidates;
}

export async function getMangaById(mangaId: string): Promise<MangaDexCandidate> {
  const url = new URL(`${MANGADEX_API_BASE}/manga/${mangaId}`);
  url.searchParams.append('includes[]', 'cover_art');

  const response = await fetch(url.toString(), {
    headers: getMangaDexHeaders(),
  });

  if (response.status === 429) {
    throw new Error('MangaDex Rate Limit exceeded');
  }
  if (response.status === 404) {
    throw new Error(`MangaDex manga not found: ${mangaId}`);
  }
  if (!response.ok) {
    throw new Error(`MangaDex API error: ${response.status}`);
  }

  const data = await response.json();
  const manga = mergeRelationshipsSingle(data.data, data.included || []);
  
  const attrs = manga.attributes;
  const title = attrs.title.en || Object.values(attrs.title)[0] as string;
  const altTitles = attrs.altTitles.map((t: any) => Object.values(t)[0] as string);
  const description = attrs.description.en || Object.values(attrs.description)[0] as string || '';
  
  const coverUrl = selectBestCoverFromRelationships(manga.relationships, manga.id);

  const genres = attrs.tags
    .filter((tag: any) => tag.attributes.group === 'genre')
    .map((tag: any) => tag.attributes.name.en);

  return {
    mangadex_id: manga.id,
    title,
    alternative_titles: Array.from(new Set(altTitles)),
    description,
    status: attrs.status,
    type: attrs.publicationDemographic || 'unknown',
    genres,
    content_rating: attrs.contentRating,
    cover_url: coverUrl,
    source: 'mangadex',
  };
}
