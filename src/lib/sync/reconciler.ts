import { SyncAction, SyncOutbox } from './outbox';

const MAX_RETRIES = 5;

export const SyncReconciler = {
  async processOutbox() {
    if (typeof window === 'undefined' || !navigator.onLine) return;

    const actions = SyncOutbox.getActions();
    if (actions.length === 0) return;

    // Sort by timestamp to preserve order of operations
    const sortedActions = [...actions].sort((a, b) => a.timestamp - b.timestamp);

    for (const action of sortedActions) {
      if (action.retryCount >= MAX_RETRIES) {
        console.warn(`Action ${action.id} exceeded max retries, skipping.`);
        continue;
      }

      try {
        const success = await this.executeAction(action);
        if (success) {
          SyncOutbox.dequeue(action.id);
        } else {
          SyncOutbox.updateRetry(action.id);
        }
      } catch (error) {
        console.error(`Failed to process action ${action.id}:`, error);
        SyncOutbox.updateRetry(action.id);
      }
    }
  },

  async executeAction(action: SyncAction): Promise<boolean> {
    const { type, payload } = action;

    switch (type) {
      case 'CHAPTER_READ':
        return this.handleChapterRead(payload);
      case 'LIBRARY_UPDATE':
        return this.handleLibraryUpdate(payload);
      case 'LIBRARY_DELETE':
        return this.handleLibraryDelete(payload);
      case 'SETTING_UPDATE':
        return this.handleSettingUpdate(payload);
      default:
        return true; // Unknown actions are considered "processed"
    }
  },

  async handleChapterRead(payload: { entryId: string; chapterNumber: number; sourceId?: string }) {
    const response = await fetch(`/api/library/${payload.entryId}/progress`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chapterNumber: payload.chapterNumber,
        sourceId: payload.sourceId,
      }),
    });
    return response.ok || response.status === 409; // 409 handled as success (already processed)
  },

  async handleLibraryUpdate(payload: { entryId: string; status?: string; rating?: number }) {
    const response = await fetch(`/api/library/${payload.entryId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        status: payload.status,
        rating: payload.rating,
      }),
    });
    return response.ok;
  },

  async handleLibraryDelete(payload: { entryId: string }) {
    const response = await fetch(`/api/library/${payload.entryId}`, {
      method: 'DELETE',
    });
    return response.ok || response.status === 404; // 404 means already deleted
  },

  async handleSettingUpdate(payload: { userId: string; settings: any }) {
    // Assuming there's a user settings endpoint
    const response = await fetch(`/api/users/me`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload.settings),
    });
    return response.ok;
  }
};
