"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import api from "@/lib/api";
import ScanStatusBadge from "@/components/scanner/ScanStatusBadge";
import ScanProgressBar from "@/components/scanner/ScanProgressBar";
import { useTranslation } from "@/i18n";

interface ScanSummary {
  id: string;
  source_type: string;
  source_url: string;
  source_filename?: string;
  status: string;
  created_at: string;
  completed_at: string | null;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  security_score: number | null;
  detected_languages: string[];
}

function projectName(scan: ScanSummary): string {
  if (scan.source_type === "dast") {
    return scan.source_filename || scan.source_url || "DAST Scan";
  }
  if (scan.source_url) {
    const parts = scan.source_url.replace(/\.git$/, "").split("/");
    return parts[parts.length - 1] || "Unknown";
  }
  return scan.source_filename || (scan.source_type === "zip" ? "ZIP Upload" : "File Upload");
}

export default function ScansPage() {
  const { t } = useTranslation();
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get("/api/scanner/scans/")
      .then((res) => setScans(res.data))
      .catch((err) => { if (err?.response?.status !== 401) console.error("Failed to fetch scans", err); })
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-(--text)">{t("app.scans.title")}</h1>
        <Link
          href="/dashboard"
          className="inline-flex items-center gap-2 rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white hover:bg-(--accent-hover)"
        >
          <span className="material-symbols-outlined text-base" aria-hidden>add</span>
          {t("app.scans.newScan")}
        </Link>
      </div>

      {loading ? (
        <div className="rounded-xl border border-(--border) bg-(--bg-card) p-8 text-center">
          <span className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-blue-500/30 border-t-blue-400" />
          <p className="mt-2 text-sm text-(--text-muted)">{t("app.scans.loading")}</p>
        </div>
      ) : scans.length === 0 ? (
        <div className="rounded-xl border border-(--border) bg-(--bg-card) p-8 text-center text-(--text-muted)">
          <p>{t("app.scans.noScans")}</p>
        </div>
      ) : (
        <div className="space-y-5">
          {scans.map((scan) => {
            const name = projectName(scan);
            const duration =
              scan.completed_at && scan.created_at
                ? `${Math.round((new Date(scan.completed_at).getTime() - new Date(scan.created_at).getTime()) / 1000)}s`
                : null;

            return (
              <Link
                key={scan.id}
                href={`/scans/${scan.id}`}
                className="mt-4 flex items-center gap-4 rounded-xl border border-(--border) bg-(--bg-card) p-5 transition-colors hover:bg-white/5"
              >
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-(--accent)/20">
                  <span className="material-symbols-outlined text-(--accent)" aria-hidden>
                    {scan.source_type === "git" ? "source_notes" : scan.source_type === "zip" ? "folder_zip" : "upload_file"}
                  </span>
                </div>

                <div className="min-w-0 flex-1">
                  <p className="truncate font-medium text-(--text)">{name}</p>
                  <p className="mt-0.5 truncate text-xs text-(--text-muted)">
                    {scan.source_url || scan.source_type.toUpperCase()} &middot;{" "}
                    {new Date(scan.created_at).toLocaleString()}
                    {duration && <> &middot; {duration}</>}
                  </p>
                </div>

                <div className="flex shrink-0 items-center gap-4">
                  {scan.status === "completed" && (
                    <div className="flex gap-3 text-xs">
                      {scan.critical_count > 0 && <span className="text-(--critical)">{scan.critical_count} critical</span>}
                      {scan.high_count > 0 && <span className="text-(--high)">{scan.high_count} high</span>}
                      {scan.medium_count > 0 && <span className="text-(--medium)">{scan.medium_count} med</span>}
                      {scan.total_findings === 0 && <span className="text-(--success)">{t("app.scans.noIssues")}</span>}
                    </div>
                  )}
                  {scan.status !== "completed" && scan.status !== "failed" && (
                    <div className="w-32">
                      <ScanProgressBar status={scan.status} />
                    </div>
                  )}
                  <ScanStatusBadge status={scan.status} />
                </div>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
