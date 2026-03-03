"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import SeverityChart from "@/components/dashboard/SeverityChart";
import type { StackedChartData } from "@/components/dashboard/SeverityChart";
import SeverityDonutChart from "@/components/dashboard/SeverityDonutChart";
import ScanTimelineChart from "@/components/dashboard/ScanTimelineChart";
import TopFilesChart from "@/components/dashboard/TopFilesChart";
import PwnForm from "@/components/scanner/PwnForm";
import SubmitForm from "@/components/scanner/SubmitForm";
import { useTranslation } from "@/i18n";
import api from "@/lib/api";

interface DashboardStats {
  total_scans: number;
  completed_scans: number;
  total_findings: number;
  total_critical: number;
  total_high: number;
  total_medium: number;
  total_low: number;
  avg_score: number;
  max_cvss: number;
}

interface RecentScan {
  id: string;
  source_url: string;
  source_type: string;
  source_filename?: string;
  status: string;
  created_at: string;
  total_findings: number;
  security_score: number | null;
}

/**
 * Page d'accueil : nouveau scan, cartes récapitulatives, scans récents.
 */
export default function DashboardPage() {
  const { t } = useTranslation();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [owaspData, setOwaspData] = useState<StackedChartData>([]);
  const [topFiles, setTopFiles] = useState<{ file_path: string; count: number }[]>([]);

  useEffect(() => {
    api.get("/api/scanner/stats/").then((r) => setStats(r.data)).catch((err) => { if (err?.response?.status !== 401) console.error("Failed to fetch stats", err); });
    api.get("/api/scanner/scans/?page_size=10").then((r) => {
      const data = r.data;
      setRecentScans(Array.isArray(data) ? data.slice(0, 10) : (data.results ?? []).slice(0, 10));
    }).catch((err) => { if (err?.response?.status !== 401) console.error("Failed to fetch recent scans", err); });
    api.get("/api/scanner/owasp-chart/").then((r) => setOwaspData(r.data)).catch((err) => { if (err?.response?.status !== 401) console.error("Failed to fetch OWASP chart", err); });
    api.get("/api/scanner/top-files/").then((r) => setTopFiles(r.data)).catch((err) => { if (err?.response?.status !== 401) console.error("Failed to fetch top files", err); });
  }, []);

  function projectName(scan: RecentScan): string {
    if (scan.source_url) {
      const parts = scan.source_url.replace(/\.git$/, "").split("/");
      return parts[parts.length - 1] || "Unknown";
    }
    return scan.source_filename || (scan.source_type === "zip" ? "ZIP Upload" : "File Upload");
  }

  const statusColors: Record<string, string> = {
    completed: "text-(--success)",
    failed: "text-(--critical)",
    scanning: "text-(--medium)",
    pending: "text-(--text-muted)",
    cloning: "text-(--medium)",
    detecting: "text-(--medium)",
    aggregating: "text-(--medium)",
  };

  return (
    <div className="flex flex-col gap-8">
      <h1 className="text-2xl font-bold text-(--text)">{t("app.dashboard.title")}</h1>
      <p className="mt-3 text-sm leading-relaxed text-(--text-muted)">
        {t("app.dashboard.subtitle")}
      </p>
      {/* PWN Mon Site */}
      <PwnForm />

      {/* Section Nouveau scan */}
      <SubmitForm />

      {/* Cartes récap */}
      <div className="grid gap-5 sm:grid-cols-3">
        {/* Carte 1 : Total Vulnerabilities */}
        <div className="relative rounded-xl border border-(--border) bg-(--bg-card) px-6 py-5">
          <span
            className="material-symbols-outlined absolute right-2 top-2 text-(--text-muted) opacity-40"
            aria-hidden
          >
            bug_report
          </span>
          <p className="text-sm font-medium text-(--text-muted)">
            {t("app.dashboard.totalVulnerabilities")}
          </p>
          <p className="mt-2 text-2xl font-bold text-(--text)">
            {stats ? stats.total_findings : "—"}
          </p>
          <p className="mt-2 flex items-center gap-1.5 text-xs text-(--critical)">
            <span className="material-symbols-outlined text-sm">trending_up</span>
            {stats ? `${stats.total_critical} critical` : t("app.dashboard.thisWeek")}
          </p>
        </div>
        {/* Carte 2 : Scans Completed */}
        <div className="relative rounded-xl border border-(--border) bg-(--bg-card) px-6 py-5">
          <span
            className="material-symbols-outlined absolute right-2 top-2 text-(--text-muted) opacity-40"
            aria-hidden
          >
            history
          </span>
          <p className="text-sm font-medium text-(--text-muted)">
            {t("app.dashboard.scansCompleted")}
          </p>
          <p className="mt-2 text-2xl font-bold text-(--text)">
            {stats ? stats.completed_scans : "—"}
          </p>
          <p className="mt-2 flex items-center gap-1.5 text-xs text-(--success)">
            <span className="material-symbols-outlined text-sm">check_circle</span>
            {stats ? `${stats.total_scans} total` : t("app.dashboard.allOperational")}
          </p>
        </div>
        {/* Carte 3 : Avg Security Score */}
        <div className="relative rounded-xl border border-(--border) bg-(--bg-card) px-6 py-5">
          <span
            className="material-symbols-outlined absolute right-2 top-2 text-(--text-muted) opacity-40"
            aria-hidden
          >
            report_problem
          </span>
          <p className="text-sm font-medium text-(--text-muted)">
            {t("app.dashboard.criticalIssues")}
          </p>
          <p className="mt-2 text-2xl font-bold text-(--critical)">
            {stats ? stats.total_critical : "—"}
          </p>
          <p className="mt-2 flex items-center gap-1.5 text-xs text-(--high)">
            <span className="material-symbols-outlined text-sm">warning</span>
            {stats ? `Avg score: ${stats.avg_score}/100` : t("app.dashboard.actionRequired")}
          </p>
        </div>
      </div>

      {/* Recent Scans */}
      <div>
        <div className="mb-6 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-(--text)">{t("app.dashboard.recentScans")}</h2>
          <Link href="/scans" className="text-sm text-(--accent) hover:underline">
            {t("app.dashboard.viewAll")}
          </Link>
        </div>
        <section className="rounded-xl border border-(--border) bg-(--bg-card) p-6">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-(--border) text-left text-(--text-muted)">
                  <th className="pb-4 pl-6 pr-4 font-medium text-(--text)">
                    {t("app.dashboard.projectName")}
                  </th>
                  <th className="pb-4 pr-4 font-medium text-(--text)">
                    {t("app.dashboard.repository")}
                  </th>
                  <th className="pb-4 pr-4 font-medium text-(--text)">{t("app.dashboard.date")}</th>
                  <th className="pb-4 pr-4 font-medium text-(--text)">{t("app.dashboard.status")}</th>
                  <th className="pb-4 pr-6 font-medium text-(--text)">{t("app.dashboard.actions")}</th>
                </tr>
              </thead>
              <tbody className="text-(--text)">
                {recentScans.length === 0 ? (
                  <tr className="border-b border-(--border)">
                    <td colSpan={5} className="py-8 text-center text-(--text-muted)">
                      {t("app.dashboard.noScansYet")}
                    </td>
                  </tr>
                ) : (
                  recentScans.slice(0, 5).map((scan) => (
                    <tr key={scan.id} className="border-b border-(--border) hover:bg-white/5 transition-colors">
                      <td className="py-3 pl-6 pr-4 font-medium">{projectName(scan)}</td>
                      <td className="py-3 pr-4 font-mono text-xs text-(--text-muted) max-w-[200px] truncate">
                        {scan.source_url || scan.source_type}
                      </td>
                      <td className="py-3 pr-4 text-xs text-(--text-muted)">
                        {new Date(scan.created_at).toLocaleDateString()}
                      </td>
                      <td className={`py-3 pr-4 text-xs font-medium ${statusColors[scan.status] ?? "text-(--text-muted)"}`}>
                        {scan.status}
                      </td>
                      <td className="py-3 pr-6">
                        <Link
                          href={`/scans/${scan.id}`}
                          className="text-xs text-(--accent) hover:underline"
                        >
                          View
                        </Link>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      {/* Charts grid — 2x2 on large screens */}
      <div className="grid gap-5 grid-cols-1 lg:grid-cols-2">
        {/* Distribution OWASP (graphique recharts) */}
        <section className="rounded-xl border border-(--border) bg-(--bg-card) p-6">
          <h2 className="text-base font-semibold text-(--text)">
            {t("app.dashboard.owaspDistribution")}
          </h2>
          <p className="mt-2 text-xs text-(--text-muted)">
            {t("app.dashboard.runScanToSee")}
          </p>
          <div className="mt-4">
            <SeverityChart stackedData={owaspData.length ? owaspData : undefined} />
          </div>
        </section>

        {/* Severity Donut Chart */}
        <section className="rounded-xl border border-(--border) bg-(--bg-card) p-6">
          <h2 className="text-base font-semibold text-(--text)">Severity Breakdown</h2>
          <p className="mt-2 text-xs text-(--text-muted)">Distribution by severity level</p>
          <div className="mt-4">
            <SeverityDonutChart
              critical={stats?.total_critical ?? 0}
              high={stats?.total_high ?? 0}
              medium={stats?.total_medium ?? 0}
              low={stats?.total_low ?? 0}
            />
          </div>
        </section>

        {/* Scan Timeline Chart */}
        <section className="rounded-xl border border-(--border) bg-(--bg-card) p-6">
          <h2 className="text-base font-semibold text-(--text)">Security Score Timeline</h2>
          <p className="mt-2 text-xs text-(--text-muted)">Score evolution across recent scans</p>
          <div className="mt-4">
            <ScanTimelineChart scans={recentScans} />
          </div>
        </section>

        {/* Top Vulnerable Files Chart */}
        <section className="rounded-xl border border-(--border) bg-(--bg-card) p-6">
          <h2 className="text-base font-semibold text-(--text)">Top Vulnerable Files</h2>
          <p className="mt-2 text-xs text-(--text-muted)">Files with the most findings</p>
          <div className="mt-4">
            <TopFilesChart files={topFiles} />
          </div>
        </section>
      </div>

    </div>
  );
}
