"use client";

import { useEffect, useRef, useState } from "react";
import axios from "axios";
import api from "@/lib/api";

/**
 * Shape of a scan returned by GET /api/scanner/scans/<id>/
 * Matches ScanStatusSerializer fields.
 */
export interface ScanStatus {
  id: string;
  source_type: "git" | "zip" | "files";
  source_url: string;
  source_filename: string;
  status:
    | "pending"
    | "cloning"
    | "detecting"
    | "scanning"
    | "aggregating"
    | "completed"
    | "failed";
  detected_languages: string[];
  error_message: string;
  created_at: string;
  completed_at: string | null;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  security_score: number | null;
}

const POLL_INTERVAL_MS = 3000; // 3 seconds per research recommendation
const TERMINAL_STATUSES = new Set(["completed", "failed"]);

/**
 * useScanStatus — polls GET /api/scanner/scans/<scanId>/ every 3 seconds.
 *
 * Stops polling automatically when the scan reaches a terminal status
 * (completed or failed) or on network error.
 *
 * @param scanId - UUID string of the scan to poll, or null to skip
 * @returns { scan, error }
 */
export function useScanStatus(scanId: string | null): {
  scan: ScanStatus | null;
  error: string | null;
} {
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const clearPolling = () => {
    if (intervalRef.current !== null) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  };

  useEffect(() => {
    if (!scanId) return;

    const fetchStatus = async () => {
      try {
        const res = await api.get<ScanStatus>(
          `/api/scanner/scans/${scanId}/`
        );
        setScan(res.data);

        if (TERMINAL_STATUSES.has(res.data.status)) {
          clearPolling();
        }
      } catch (err: unknown) {
        const message =
          axios.isAxiosError(err)
            ? err.response?.data?.detail ?? err.message
            : "Failed to fetch scan status";
        setError(message);
        clearPolling();
      }
    };

    // Fetch immediately, then start polling
    fetchStatus();
    intervalRef.current = setInterval(fetchStatus, POLL_INTERVAL_MS);

    return () => {
      clearPolling();
    };
  }, [scanId]);

  return { scan, error };
}
