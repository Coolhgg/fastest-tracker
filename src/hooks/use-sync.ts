'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import { SyncOutbox } from '@/lib/sync/outbox';
import { SyncReconciler } from '@/lib/sync/reconciler';

export function useSync() {
  const [isOnline, setIsOnline] = useState(true);
  const [pendingCount, setPendingCount] = useState(0);
  const [isSyncing, setIsSyncing] = useState(false);
  const isSyncingRef = useRef(false);

  const updateStatus = useCallback(() => {
    setIsOnline(navigator.onLine);
    setPendingCount(SyncOutbox.getActions().length);
  }, []);

  const sync = useCallback(async () => {
    if (!navigator.onLine || isSyncingRef.current) return;
    
    isSyncingRef.current = true;
    setIsSyncing(true);
    try {
      await SyncReconciler.processOutbox();
    } finally {
      isSyncingRef.current = false;
      setIsSyncing(false);
      updateStatus();
    }
  }, [updateStatus]);

  useEffect(() => {
    if (typeof window === 'undefined') return;

    // Initial status
    updateStatus();

    // Listen for connectivity changes
    window.addEventListener('online', sync);
    window.addEventListener('offline', updateStatus);
    
    // Listen for outbox changes (from other hooks or tabs)
    window.addEventListener('sync-outbox-updated', updateStatus);
    
    // Auto-sync on mount if online
    if (navigator.onLine) {
      sync();
    }

    // Periodic sync attempt (e.g. every 5 minutes)
    const interval = setInterval(sync, 5 * 60 * 1000);

    return () => {
      window.removeEventListener('online', sync);
      window.removeEventListener('offline', updateStatus);
      window.removeEventListener('sync-outbox-updated', updateStatus);
      clearInterval(interval);
    };
  }, [sync, updateStatus]);

  return {
    isOnline,
    pendingCount,
    isSyncing,
    sync
  };
}
