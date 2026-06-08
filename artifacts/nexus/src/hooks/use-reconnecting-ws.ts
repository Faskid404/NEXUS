import { useRef, useCallback, useState, useEffect } from "react";

const BACKOFF_MS = [1_000, 2_000, 4_000, 8_000, 16_000, 30_000] as const;
const MAX_RETRIES = 5;

export type WsStatus =
  | "idle"
  | "connecting"
  | "open"
  | "reconnecting"
  | "failed"
  | "closed";

export interface ReconnectInfo {
  attempt:     number;
  maxAttempts: number;
  delayMs:     number;
}

export interface UseReconnectingWsReturn {
  status:        WsStatus;
  reconnectInfo: ReconnectInfo | null;
  connect:       (url: string, payload: unknown) => void;
  disconnect:    () => void;
  send:          (msg: unknown) => void;
}

export function useReconnectingWs(options: {
  onMessage: (msg: unknown) => void;
  onOpen?:   () => void;
  onClose?:  (wasClean: boolean) => void;
}): UseReconnectingWsReturn {
  const [status,        setStatus]        = useState<WsStatus>("idle");
  const [reconnectInfo, setReconnectInfo] = useState<ReconnectInfo | null>(null);

  const wsRef         = useRef<WebSocket | null>(null);
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const stoppedRef    = useRef(true);
  const attemptRef    = useRef(0);

  const cbRef = useRef(options);
  cbRef.current = options;

  const openSocketRef = useRef<(url: string, payload: unknown) => void>(() => {});

  const cancelRetry = useCallback(() => {
    if (retryTimerRef.current) {
      clearTimeout(retryTimerRef.current);
      retryTimerRef.current = null;
    }
  }, []);

  const openSocket = useCallback(
    (url: string, payload: unknown) => {
      const old = wsRef.current;
      wsRef.current = null;
      if (old && old.readyState < WebSocket.CLOSING) old.close(1000, "reconnect");

      setStatus("connecting");
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        if (ws !== wsRef.current) return;
        attemptRef.current = 0;
        setStatus("open");
        setReconnectInfo(null);
        try { ws.send(JSON.stringify(payload)); } catch { /* ignore */ }
        cbRef.current.onOpen?.();
      };

      ws.onmessage = (ev: MessageEvent<string>) => {
        if (ws !== wsRef.current) return;
        try { cbRef.current.onMessage(JSON.parse(ev.data)); } catch { /* ignore */ }
      };

      ws.onerror = () => { /* handled in onclose */ };

      ws.onclose = (ev: CloseEvent) => {
        if (ws !== wsRef.current) return;
        wsRef.current = null;
        const wasClean = ev.code === 1000 || ev.code === 1001;

        if (stoppedRef.current || wasClean) {
          setStatus("closed");
          setReconnectInfo(null);
          cbRef.current.onClose?.(wasClean);
          return;
        }

        const attempt = attemptRef.current + 1;
        attemptRef.current = attempt;

        if (attempt > MAX_RETRIES) {
          setStatus("failed");
          setReconnectInfo(null);
          cbRef.current.onClose?.(false);
          return;
        }

        const delayMs =
          BACKOFF_MS[Math.min(attempt - 1, BACKOFF_MS.length - 1)] ?? 30_000;
        setStatus("reconnecting");
        setReconnectInfo({ attempt, maxAttempts: MAX_RETRIES, delayMs });

        retryTimerRef.current = setTimeout(() => {
          if (!stoppedRef.current) openSocketRef.current(url, payload);
        }, delayMs);
      };
    },
    [cancelRetry],
  );

  openSocketRef.current = openSocket;

  const connect = useCallback(
    (url: string, payload: unknown) => {
      cancelRetry();
      stoppedRef.current = false;
      attemptRef.current = 0;
      openSocket(url, payload);
    },
    [cancelRetry, openSocket],
  );

  const disconnect = useCallback(() => {
    cancelRetry();
    stoppedRef.current = true;
    const ws = wsRef.current;
    wsRef.current = null;
    if (ws && ws.readyState < WebSocket.CLOSING) ws.close(1000, "user disconnect");
    setStatus("closed");
    setReconnectInfo(null);
    cbRef.current.onClose?.(true);
  }, [cancelRetry]);

  const send = useCallback((msg: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    }
  }, []);

  useEffect(
    () => () => {
      cancelRetry();
      stoppedRef.current = true;
      const ws = wsRef.current;
      wsRef.current = null;
      if (ws && ws.readyState < WebSocket.CLOSING) ws.close(1000, "unmount");
    },
    [cancelRetry],
  );

  return { status, reconnectInfo, connect, disconnect, send };
}
