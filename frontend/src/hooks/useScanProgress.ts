import { useEffect, useRef, useState, useCallback } from 'react';
import { ScanProgress, TaskStatus } from '@/types';

interface UseScanProgressOptions {
  taskId?: string;
  onProgress?: (progress: ScanProgress) => void;
  onComplete?: (progress: ScanProgress) => void;
  onError?: (error: Event) => void;
  enabled?: boolean;
}

export const useScanProgress = (options: UseScanProgressOptions) => {
  const { taskId, onProgress, onComplete, onError, enabled = true } = options;
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const connect = useCallback(() => {
    if (!taskId || !enabled) return;

    try {
      const eventSource = new EventSource(`/api/scan-tasks/${taskId}/progress`);
      eventSourceRef.current = eventSource;

      eventSource.onopen = () => {
        setIsConnected(true);
      };

      eventSource.onmessage = (event) => {
        try {
          const data: ScanProgress = JSON.parse(event.data);
          setProgress(data);
          onProgress?.(data);

          if (data.status === 'completed' || data.status === 'failed' || data.status === 'cancelled') {
            onComplete?.(data);
            eventSource.close();
            setIsConnected(false);
          }
        } catch {
          console.error('Failed to parse SSE message:', event.data);
        }
      };

      eventSource.onerror = (error) => {
        setIsConnected(false);
        onError?.(error);
        eventSource.close();

        // Auto reconnect after 3 seconds
        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, 3000);
      };
    } catch (error) {
      console.error('Failed to connect to SSE:', error);
      setIsConnected(false);
    }
  }, [taskId, enabled, onProgress, onComplete, onError]);

  const disconnect = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    setIsConnected(false);
  }, []);

  useEffect(() => {
    if (enabled && taskId) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [taskId, enabled, connect, disconnect]);

  return {
    progress,
    isConnected,
    connect,
    disconnect,
  };
};

export default useScanProgress;
