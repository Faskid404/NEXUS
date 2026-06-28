import { useRef, useCallback, useState, useEffect } from "react";

const BASE_DELAYS_MS = [1_000, 2_000, 4_000, 8_000, 16_000, 30_000] as const;
const JITTER_FACTOR  = 0.35;

function withJitter(base: number): number {
  return Math.round(base * (1 - JITTER_FACTOR / 2 + Math.random() * JITTER_FACTOR));
}

export type WsStatus =
  | "idle"
  | "connecting"
  | "open"
  | "reconnecting"
  | "failed"
  | "closed";

export interface ReconnectInfo {
  attempt:     number;
  maxAttempts: number | "infinite";
  delayMs:     number;
}

export interface UseReconnectingWsOptions {
  onMessage:    (msg: unknown) => void;
  onOpen?:      () => void;
  onClose?:     (wasClean: boolean) => void;
  onReconnect?: (info: ReconnectInfo) => void;
  maxRetries?:  number | "infinite";
}

export interface UseReconnectingWsReturn {
  status:        WsStatus;
  reconnectInfo: ReconnectInfo | null;
  connect:       (url: string, payload: unknown) => void;
  disconnect:    () => void;
  send:          (msg: unknown) => void;
}

export function useReconnectingWs(options: UseReconnectingWsOptions): UseReconnectingWsReturn {
  const [status,        setStatus]        = useState<WsStatus>("idle");
  const [reconnectInfo, setReconnectInfo] = useState<ReconnectInfo | null>(null);

  const wsRef         = useRef<WebSocket | null>(null);
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const stoppedRef    = useRef(true);
  const attemptRef    = useRef(0);
  const urlRef        = useRef<string>("");
  const payloadRef    = useRef<unknown>(null);

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
      urlRef.current     = url;
      payloadRef.current = payload;

      const old = wsRef.current;
      wsRef.current = null;
      if (old && old.readyState < WebSocket.CLOSING) {
        try { old.close(1000, "reconnect"); } catch { }
      }

      setStatus("connecting");
      let ws: WebSocket;
      try {
        ws = new WebSocket(url);
      } catch {
        setStatus("failed");
        setReconnectInfo(null);
        cbRef.current.onClose?.(false);
        return;
      }
      wsRef.current = ws;

      ws.onopen = () => {
        if (ws !== wsRef.current) return;
        attemptRef.current = 0;
        setStatus("open");
        setReconnectInfo(null);
        try { ws.send(JSON.stringify(payload)); } catch { }
        cbRef.current.onOpen?.();
      };

      ws.onmessage = (ev: MessageEvent) => {
        if (ws !== wsRef.current) return;
        try {
          const data = typeof ev.data === "string" ? JSON.parse(ev.data) : ev.data;
          cbRef.current.onMessage(data);
        } catch { }
      };

      ws.onerror = () => {
        // Trigger close path so reconnect logic kicks in
        if (ws === wsRef.current) ws.close();
      };

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

        const attempt    = attemptRef.current + 1;
        const maxRetries = cbRef.current.maxRetries ?? 8;
        attemptRef.current = attempt;

        if (maxRetries !== "infinite" && attempt > maxRetries) {
          setStatus("failed");
          setReconnectInfo(null);
          cbRef.current.onClose?.(false);
          return;
        }

        const baseIdx = Math.min(attempt - 1, BASE_DELAYS_MS.length - 1);
        const base    = BASE_DELAYS_MS[baseIdx] ?? 30_000;
        const delayMs = withJitter(base);
        const info: ReconnectInfo = { attempt, maxAttempts: maxRetries, delayMs };

        setStatus("reconnecting");
        setReconnectInfo(info);
        cbRef.current.onReconnect?.(info);

        retryTimerRef.current = setTimeout(() => {
          if (!stoppedRef.current) openSocketRef.current(urlRef.current, payloadRef.current);
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
    if (ws && ws.readyState < WebSocket.CLOSING) {
      try { ws.close(1000, "user disconnect"); } catch { }
    }
    setStatus("closed");
    setReconnectInfo(null);
    cbRef.current.onClose?.(true);
  }, [cancelRetry]);

  const send = useCallback((msg: unknown) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    try { ws.send(JSON.stringify(msg)); } catch { }
  }, []);

  useEffect(
    () => () => {
      cancelRetry();
      stoppedRef.current = true;
      const ws = wsRef.current;
      wsRef.current = null;
      if (ws && ws.readyState < WebSocket.CLOSING) {
        try { ws.close(1000, "unmount"); } catch { }
      }
    },
    [cancelRetry],
  );

  return { status, reconnectInfo, connect, disconnect, send };
}
