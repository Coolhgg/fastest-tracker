export type SyncActionType = 'LIBRARY_UPDATE' | 'CHAPTER_READ' | 'SETTING_UPDATE' | 'LIBRARY_DELETE';

export interface SyncAction {
  id: string;
  type: SyncActionType;
  payload: any;
  timestamp: number;
  retryCount: number;
}

const OUTBOX_KEY = 'kenmei_sync_outbox';

export const SyncOutbox = {
  getActions(): SyncAction[] {
    if (typeof window === 'undefined') return [];
    const stored = localStorage.getItem(OUTBOX_KEY);
    return stored ? JSON.parse(stored) : [];
  },

  enqueue(type: SyncActionType, payload: any) {
    const actions = this.getActions();
    const newAction: SyncAction = {
      id: crypto.randomUUID(),
      type,
      payload,
      timestamp: Date.now(),
      retryCount: 0,
    };
    
    // Deduplication logic
    let updatedActions = actions;
    if (type === 'CHAPTER_READ') {
      // If we're marking the same chapter read, just update the timestamp/payload
      updatedActions = actions.filter(a => 
        !(a.type === 'CHAPTER_READ' && 
          a.payload.entryId === payload.entryId && 
          a.payload.chapterNumber === payload.chapterNumber)
      );
    } else if (type === 'LIBRARY_UPDATE') {
      // If we're updating the same entry, keep only the latest update
      updatedActions = actions.filter(a => 
        !(a.type === 'LIBRARY_UPDATE' && a.payload.entryId === payload.entryId)
      );
    }

    updatedActions.push(newAction);
    localStorage.setItem(OUTBOX_KEY, JSON.stringify(updatedActions));
    
    // Dispatch event for hooks to listen to
    window.dispatchEvent(new Event('sync-outbox-updated'));
    return newAction.id;
  },

  dequeue(id: string) {
    const actions = this.getActions();
    const updated = actions.filter(a => a.id !== id);
    localStorage.setItem(OUTBOX_KEY, JSON.stringify(updated));
    window.dispatchEvent(new Event('sync-outbox-updated'));
  },

  updateRetry(id: string) {
    const actions = this.getActions();
    const action = actions.find(a => a.id === id);
    if (action) {
      action.retryCount += 1;
      localStorage.setItem(OUTBOX_KEY, JSON.stringify(actions));
    }
  },

  clear() {
    localStorage.removeItem(OUTBOX_KEY);
    window.dispatchEvent(new Event('sync-outbox-updated'));
  }
};
