"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import api from "@/lib/api";

export interface PwnProgress {
  percent: number;
  phase: string;
  phase_label: string;
  message: string;
  findings_so_far: number;
  etaSeconds: number | null;
}

export type PwnState =
  | { status: "idle" }
  | { status: "running"; scanId: string; progress: PwnProgress }
  | { status: "completed"; scanId: string; totalFindings: number }
  | { status: "failed"; scanId: string; error: string };

const STORAGE_KEY = "pwn_active_scan_id";
const POLL_INTERVAL = 3000;
const WS_RECONNECT_DELAY = 2000;

/**
 * Hook for PWN Mon Site scan progress via WebSocket with polling fallback.
 * Persists active scan ID in localStorage so progress survives navigation.
 */
export function usePwnProgress(): {
  state: PwnState;
  startPwn: (url: string) => Promise<void>;
  reset: () => void;
} {
  const [state, setState] = useState<PwnState>({ status: "idle" });
  const wsRef = useRef<WebSocket | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const mountedRef = useRef(true);
  const startedAtRef = useRef<number | null>(null);

  const computeEta = (percent: number): number | null => {
    if (!startedAtRef.current || percent <= 2) return null;
    const elapsed = (Date.now() - startedAtRef.current) / 1000;
    const remaining = (elapsed / percent) * (100 - percent);
    return Math.round(remaining);
  };

  const cleanup = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const connectWs = useCallback(
    (scanId: string) => {
      if (typeof window === "undefined") return;

      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      const wsUrl = `${proto}//${window.location.host}/ws/scan/${scanId}/`;

      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onmessage = (event) => {
          if (!mountedRef.current) return;
          try {
            const data = JSON.parse(event.data);

            if (data.type === "progress") {
              const pct = data.percent ?? 0;
              setState({
                status: "running",
                scanId,
                progress: {
                  percent: pct,
                  phase: data.phase ?? "",
                  phase_label: data.phase_label ?? "",
                  message: data.message ?? "",
                  findings_so_far: data.findings_so_far ?? 0,
                  etaSeconds: computeEta(pct),
                },
              });
            } else if (data.type === "completed") {
              localStorage.removeItem(STORAGE_KEY);
              setState({
                status: "completed",
                scanId,
                totalFindings: data.total_findings ?? 0,
              });
              cleanup();
            } else if (data.type === "failed") {
              localStorage.removeItem(STORAGE_KEY);
              setState({
                status: "failed",
                scanId,
                error: data.error ?? "Unknown error",
              });
              cleanup();
            }
          } catch {
            // ignore parse errors
          }
        };

        ws.onerror = () => {
          // Fallback to polling
          startPolling(scanId);
        };

        ws.onclose = () => {
          // If still running, reconnect after delay
          if (mountedRef.current) {
            const currentState = state;
            if (currentState.status === "running") {
              setTimeout(() => {
                if (mountedRef.current) connectWs(scanId);
              }, WS_RECONNECT_DELAY);
            }
          }
        };
      } catch {
        // WS not available, use polling
        startPolling(scanId);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [cleanup],
  );

  const startPolling = useCallback(
    (scanId: string) => {
      if (pollRef.current) return; // already polling

      const poll = async () => {
        try {
          const res = await api.get(`/api/scanner/scans/${scanId}/`);
          if (!mountedRef.current) return;

          const scan = res.data;

          if (scan.status === "completed") {
            localStorage.removeItem(STORAGE_KEY);
            setState({
              status: "completed",
              scanId,
              totalFindings: scan.total_findings ?? 0,
            });
            cleanup();
          } else if (scan.status === "failed") {
            localStorage.removeItem(STORAGE_KEY);
            setState({
              status: "failed",
              scanId,
              error: scan.error_message || "Scan failed",
            });
            cleanup();
          } else if (scan.progress && scan.progress.percent !== undefined) {
            const pct = scan.progress.percent ?? 0;
            setState({
              status: "running",
              scanId,
              progress: {
                percent: pct,
                phase: scan.progress.phase ?? "",
                phase_label: scan.progress.phase_label ?? "",
                message: scan.progress.message ?? "",
                findings_so_far: scan.progress.findings_so_far ?? 0,
                etaSeconds: computeEta(pct),
              },
            });
          } else {
            // Scan is in a non-terminal status but has no progress data yet
            // (e.g. pending, scanning without progress). Keep showing running.
            setState({
              status: "running",
              scanId,
              progress: {
                percent: 0,
                phase: "",
                phase_label: scan.status || "Starting...",
                message: "Waiting for scan to begin...",
                findings_so_far: 0,
                etaSeconds: null,
              },
            });
          }
        } catch {
          // ignore poll errors
        }
      };

      poll();
      pollRef.current = setInterval(poll, POLL_INTERVAL);
    },
    [cleanup],
  );

  // On mount: restore from localStorage
  useEffect(() => {
    mountedRef.current = true;
    const savedId = localStorage.getItem(STORAGE_KEY);
    if (savedId) {
      startedAtRef.current = Date.now(); // approximate for restored scans
      setState({
        status: "running",
        scanId: savedId,
        progress: {
          percent: 0,
          phase: "",
          phase_label: "Reconnecting...",
          message: "Restoring scan progress...",
          findings_so_far: 0,
          etaSeconds: null,
        },
      });
      connectWs(savedId);
      startPolling(savedId); // also poll for immediate state
    }

    return () => {
      mountedRef.current = false;
      cleanup();
    };
  }, [connectWs, startPolling, cleanup]);

  const startPwn = useCallback(
    async (url: string) => {
      cleanup();

      const res = await api.post("/api/scanner/scans/", {
        source_type: "pwn",
        source_url: url,
      });

      const scanId = res.data.id;
      localStorage.setItem(STORAGE_KEY, scanId);
      startedAtRef.current = Date.now();

      setState({
        status: "running",
        scanId,
        progress: {
          percent: 0,
          phase: "recon",
          phase_label: "Starting...",
          message: "Initializing pentest...",
          findings_so_far: 0,
          etaSeconds: null,
        },
      });

      connectWs(scanId);
      startPolling(scanId);
    },
    [cleanup, connectWs, startPolling],
  );

  const reset = useCallback(() => {
    cleanup();
    localStorage.removeItem(STORAGE_KEY);
    setState({ status: "idle" });
  }, [cleanup]);

  return { state, startPwn, reset };
}
