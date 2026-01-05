import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Merges attributes from the MangaDex 'included' array into their corresponding relationships.
 * MangaDex returns relationship objects in the main data as { id, type }, and their 
 * full objects in a separate 'included' array.
 */
export function mergeRelationships(data: any[], included: any[]) {
  if (!included || included.length === 0) return data;

  const includedMap = new Map(included.map(item => [`${item.type}:${item.id}`, item]));

  return data.map(item => {
    if (!item.relationships) return item;

    const mergedRelationships = item.relationships.map((rel: any) => {
      const includedItem = includedMap.get(`${rel.type}:${rel.id}`);
      if (includedItem) {
        return { ...rel, attributes: includedItem.attributes };
      }
      return rel;
    });

    return { ...item, relationships: mergedRelationships };
  });
}

/**
 * Single object version of mergeRelationships
 */
export function mergeRelationshipsSingle(item: any, included: any[]) {
  const [merged] = mergeRelationships([item], included);
  return merged;
}
