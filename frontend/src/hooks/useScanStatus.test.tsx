import { renderHook, waitFor, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "@/test-utils/msw-server";
import { useScanStatus } from "./useScanStatus";

describe("useScanStatus", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns null scan and null error initially", () => {
    const { result } = renderHook(() => useScanStatus(null));
    expect(result.current.scan).toBeNull();
    expect(result.current.error).toBeNull();
  });

  it("does not fetch when scanId is null", async () => {
    const { result } = renderHook(() => useScanStatus(null));
    await act(async () => {
      vi.advanceTimersByTime(5000);
    });
    expect(result.current.scan).toBeNull();
  });

  it("fetches scan status when scanId is provided", async () => {
    const { result } = renderHook(() => useScanStatus("test-scan-id"));

    await waitFor(() => {
      expect(result.current.scan).not.toBeNull();
    });

    expect(result.current.scan?.id).toBe("test-scan-id");
    expect(result.current.scan?.status).toBe("completed");
  });

  it("stops polling on completed status", async () => {
    let fetchCount = 0;
    server.use(
      http.get("/api/scanner/scans/:id/", () => {
        fetchCount++;
        return HttpResponse.json({
          id: "test-id",
          status: "completed",
          source_type: "git",
          source_url: "",
          source_filename: "",
          detected_languages: [],
          error_message: "",
          created_at: "",
          completed_at: "",
          total_findings: 0,
          critical_count: 0,
          high_count: 0,
          medium_count: 0,
          low_count: 0,
          security_score: null,
        });
      })
    );

    renderHook(() => useScanStatus("test-id"));

    await waitFor(() => {
      expect(fetchCount).toBeGreaterThanOrEqual(1);
    });

    const countAfterFirst = fetchCount;

    await act(async () => {
      vi.advanceTimersByTime(10000);
    });

    // Should not have made more requests after terminal status
    expect(fetchCount).toBe(countAfterFirst);
  });

  it("sets error on network failure", async () => {
    server.use(
      http.get("/api/scanner/scans/:id/", () => {
        return HttpResponse.error();
      })
    );

    const { result } = renderHook(() => useScanStatus("bad-id"));

    await waitFor(() => {
      expect(result.current.error).not.toBeNull();
    });
  });

  it("cleans up interval on unmount", async () => {
    server.use(
      http.get("/api/scanner/scans/:id/", () => {
        return HttpResponse.json({
          id: "scan-id",
          status: "scanning",
          source_type: "git",
          source_url: "",
          source_filename: "",
          detected_languages: [],
          error_message: "",
          created_at: "",
          completed_at: null,
          total_findings: 0,
          critical_count: 0,
          high_count: 0,
          medium_count: 0,
          low_count: 0,
          security_score: null,
        });
      })
    );

    const { unmount } = renderHook(() => useScanStatus("scan-id"));

    await waitFor(() => {});

    // Unmount should clean up without errors
    unmount();

    // Advancing time after unmount should not cause errors
    await act(async () => {
      vi.advanceTimersByTime(10000);
    });
  });
});
