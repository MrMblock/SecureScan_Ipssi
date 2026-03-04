"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import api from "@/lib/api";
import toast from "react-hot-toast";
import { useTranslation } from "@/i18n";

interface ScanSummary {
  id: string;
  source_type: string;
  source_url: string;
  source_filename?: string;
  status: "pending" | "cloning" | "detecting" | "scanning" | "aggregating" | "completed" | "failed";
  created_at: string;
  total_findings: number;
  critical_count: number;
  high_count: number;
  security_score: number | null;
}

const STATUS_CONFIG = {
  pending: { label: "Pending", dotClass: "bg-(--text-muted)", pillClass: "bg-(--text-muted)/20 text-(--text-muted)" },
  cloning: { label: "Cloning", dotClass: "bg-(--accent)", pillClass: "bg-(--accent)/20 text-(--accent)" },
  detecting: { label: "Detecting", dotClass: "bg-(--accent)", pillClass: "bg-(--accent)/20 text-(--accent)" },
  scanning: { label: "Scanning...", dotClass: "bg-(--accent)", pillClass: "bg-(--accent)/20 text-(--accent)" },
  aggregating: { label: "Aggregating", dotClass: "bg-(--accent)", pillClass: "bg-(--accent)/20 text-(--accent)" },
  completed: { label: "Completed", dotClass: "bg-(--success)", pillClass: "bg-(--success)/20 text-(--success)" },
  failed: { label: "Failed", dotClass: "bg-(--critical)", pillClass: "bg-(--critical)/20 text-(--critical)" },
};

const BG_COLORS = [
  "bg-purple-500/80", "bg-cyan-500/80", "bg-orange-500/80",
  "bg-teal-500/80", "bg-pink-500/80", "bg-indigo-500/80",
];

function projectName(scan: ScanSummary): string {
  if (scan.source_url) {
    const parts = scan.source_url.replace(/\.git$/, "").split("/");
    return parts[parts.length - 1] || "Unknown";
  }
  return scan.source_filename || (scan.source_type === "zip" ? "ZIP Upload" : "File Upload");
}

function initials(name: string): string {
  return name.slice(0, 2).toUpperCase();
}

export default function ProjectsPage() {
  const { t } = useTranslation();
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [deleting, setDeleting] = useState<string | null>(null);

  useEffect(() => {
    api
      .get("/api/scanner/scans/")
      .then((res) => setScans(res.data))
      .catch((err) => { if (err?.response?.status !== 401) console.error("Failed to fetch scans", err); })
      .finally(() => setLoading(false));
  }, []);

  const handleDelete = async (scanId: string) => {
    if (!confirm(t("app.projects.deleteConfirm"))) return;
    setDeleting(scanId);
    try {
      await api.delete(`/api/scanner/scans/${scanId}/`);
      setScans((prev) => prev.filter((s) => s.id !== scanId));
    } catch { toast.error(t("app.projects.deleteError") || "Failed to delete scan"); }
    setDeleting(null);
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-(--text)">{t("app.projects.title")}</h1>

      {loading ? (
        <div className="rounded-xl border border-(--border) bg-(--bg-card) p-8 text-center">
          <span className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-blue-500/30 border-t-blue-400" />
          <p className="mt-2 text-sm text-(--text-muted)">{t("app.projects.loading")}</p>
        </div>
      ) : scans.length === 0 ? (
        <div className="rounded-xl border border-(--border) bg-(--bg-card) p-8 text-center text-(--text-muted)">
          <p>{t("app.projects.noScans")}</p>
        </div>
      ) : (
        <section className="overflow-hidden rounded-xl border border-(--border) bg-(--bg-card) p-6">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-(--border) text-left text-(--text-muted)">
                  <th className="pb-3 pl-6 pr-4 font-medium text-(--text)">{t("app.projects.projectName")}</th>
                  <th className="pb-3 pr-4 font-medium text-(--text)">{t("app.projects.repository")}</th>
                  <th className="pb-3 pr-4 font-medium text-(--text)">{t("app.projects.date")}</th>
                  <th className="pb-3 pr-4 font-medium text-(--text)">{t("app.projects.status")}</th>
                  <th className="pb-3 pr-4 font-medium text-(--text)">{t("app.projects.findings")}</th>
                  <th className="pb-3 pr-6 font-medium text-(--text)"></th>
                </tr>
              </thead>
              <tbody className="text-(--text)">
                {scans.map((scan, i) => {
                  const name = projectName(scan);
                  const status = STATUS_CONFIG[scan.status] ?? STATUS_CONFIG.pending;
                  const bg = BG_COLORS[i % BG_COLORS.length];
                  const repo = scan.source_url
                    ? scan.source_url.replace(/^https?:\/\//, "").replace(/\.git$/, "")
                    : "—";

                  return (
                    <tr key={scan.id} className="border-b border-(--border) transition-colors hover:bg-white/5">
                      <td className="py-3 pl-6 pr-4">
                        <Link href={`/scans/${scan.id}`} className="flex items-center gap-3 hover:text-(--accent)">
                          <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded text-xs font-semibold text-white ${bg}`}>
                            {initials(name)}
                          </span>
                          <span className="font-medium">{name}</span>
                        </Link>
                      </td>
                      <td className="py-3 pr-4 text-(--text-muted)">
                        {scan.source_url ? (
                          <a href={scan.source_url} target="_blank" rel="noopener noreferrer" className="hover:text-(--accent) hover:underline">
                            {repo}
                          </a>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td className="py-3 pr-4 text-(--text-muted)">
                        {new Date(scan.created_at).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
                      </td>
                      <td className="py-3 pr-4">
                        <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${status.pillClass}`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${status.dotClass}`} />
                          {status.label}
                        </span>
                      </td>
                      <td className="py-3 pr-4">
                        {scan.status === "completed" ? (
                          <span className="text-sm">
                            {scan.total_findings}
                            {scan.critical_count > 0 && (
                              <span className="ml-1 text-xs text-(--critical)">({scan.critical_count} critical)</span>
                            )}
                          </span>
                        ) : (
                          <span className="text-(--text-muted)">—</span>
                        )}
                      </td>
                      <td className="py-3 pr-6">
                        <button
                          type="button"
                          onClick={(e) => { e.preventDefault(); handleDelete(scan.id); }}
                          disabled={deleting === scan.id}
                          className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-(--text-muted) hover:text-red-400 hover:bg-red-500/10 transition-colors disabled:opacity-50"
                          title={t("app.projects.deleteTitle")}
                        >
                          {deleting === scan.id ? (
                            <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-red-400/30 border-t-red-400" />
                          ) : (
                            <span className="material-symbols-outlined text-base" aria-hidden>delete</span>
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
