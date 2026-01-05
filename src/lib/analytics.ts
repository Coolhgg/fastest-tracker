import { supabaseAdmin } from './supabase/admin';

export interface SearchEvent {
  normalized_query: string;
  intent_type: string;
  source?: string;
  local_hit: boolean;
  external_attempted: boolean;
  results_count: number;
  resolution_time_ms: number;
  status: string;
}

/**
 * Records a search event to the database asynchronously.
 * This function is non-blocking and will not affect response times.
 */
export function recordSearchEvent(event: SearchEvent) {
  // Fire and forget - don't await this
  supabaseAdmin
    .from('search_events')
    .insert([event])
    .then(({ error }) => {
      if (error) {
        console.error('[Analytics] Failed to record search event:', error.message);
      }
    })
    .catch((err) => {
      console.error('[Analytics] Unexpected error recording search event:', err);
    });
}
