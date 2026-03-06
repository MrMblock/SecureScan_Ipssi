"use client";

import { use, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import ScanStatusBadge from "@/components/scanner/ScanStatusBadge";
import ScanProgressBar from "@/components/scanner/ScanProgressBar";
import SeverityChart from "@/components/dashboard/SeverityChart";
import type { StackedChartData } from "@/components/dashboard/SeverityChart";
import { useScanStatus } from "@/hooks/useScanStatus";
import toast, { Toaster } from "react-hot-toast";
import { useTranslation } from "@/i18n";

/* ------------------------------------------------------------------ */
/*  Types                                                             */
/* ------------------------------------------------------------------ */

interface FindingData {
  id: string;
  tool: string;
  rule_id: string;
  file_path: string;
  line_start: number | null;
  line_end: number | null;
  code_snippet: string;
  severity: string;
  owasp_category: string;
  title: string;
  description: string;
  has_fix: boolean;
  fixed_code: string;
  fix_explanation: string;
  fix_pr_url: string;
  status: string;
}

const OWASP_LABELS: Record<string, string> = {
  A01: "A01 – Broken Access Control",
  A02: "A02 – Security Misconfiguration",
  A03: "A03 – Supply Chain Failures",
  A04: "A04 – Cryptographic Failures",
  A05: "A05 – Injection",
  A06: "A06 – Insecure Design",
  A07: "A07 – Authentication Failures",
  A08: "A08 – Integrity Failures",
  A09: "A09 – Logging Failures",
  A10: "A10 – Exceptional Conditions",
  UNK: "Unknown",
};

const SEVERITY_CONFIG: Record<string, { label: string; color: string; bg: string; icon: string }> = {
  critical: { label: "Critical", color: "text-(--critical)", bg: "bg-red-500/20", icon: "error" },
  high: { label: "High", color: "text-(--high)", bg: "bg-orange-500/20", icon: "warning" },
  medium: { label: "Medium", color: "text-(--medium)", bg: "bg-yellow-500/20", icon: "info" },
  low: { label: "Low", color: "text-(--low)", bg: "bg-blue-500/20", icon: "shield" },
  info: { label: "Info", color: "text-(--text-muted)", bg: "bg-slate-500/20", icon: "help" },
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const TOOL_LABELS: Record<string, string> = {
  semgrep: "Semgrep",
  bandit: "Bandit",
  eslint: "ESLint",
  npm_audit: "npm audit",
  trufflehog: "TruffleHog",
};

const LANGUAGE_LABELS: Record<string, string> = {
  python: "Python",
  javascript: "JavaScript / TypeScript",
  php: "PHP",
  java: "Java",
  kotlin: "Kotlin",
  go: "Go",
  ruby: "Ruby",
  csharp: "C#",
  c_cpp: "C / C++",
  rust: "Rust",
  swift: "Swift",
  any: "All Languages",
};

function getExpectedAnalyzers(languages: string[]): string[] {
  const tools = new Set<string>(["trufflehog", "semgrep"]);
  if (languages.includes("python")) { tools.add("bandit"); tools.add("pip_audit"); }
  if (languages.includes("javascript")) { tools.add("eslint"); tools.add("npm_audit"); }
  if (languages.includes("php")) { tools.add("composer_audit"); }
  return [...tools].sort();
}

const ANALYZER_LABELS: Record<string, string> = {
  semgrep: "Semgrep",
  bandit: "Bandit",
  eslint: "ESLint",
  npm_audit: "npm audit",
  trufflehog: "TruffleHog",
  pip_audit: "pip-audit",
  composer_audit: "Composer Audit",
};

function projectName(sourceUrl: string, sourceType: string, sourceFilename?: string): string {
  if (sourceType === "dast") {
    return sourceFilename || sourceUrl || "DAST Scan";
  }
  if (sourceUrl) {
    const parts = sourceUrl.replace(/\.git$/, "").split("/");
    return parts[parts.length - 1] || "Unknown";
  }
  return sourceFilename || (sourceType === "zip" ? "ZIP Upload" : "File Upload");
}

/* ------------------------------------------------------------------ */
/*  Severity badge component                                          */
/* ------------------------------------------------------------------ */

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity] ?? SEVERITY_CONFIG.info;
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase ${cfg.bg} ${cfg.color}`}>
      <span className="material-symbols-outlined text-sm" aria-hidden>{cfg.icon}</span>
      {cfg.label}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/*  Filter dropdown component                                        */
/* ------------------------------------------------------------------ */

function FilterDropdown({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: { value: string; label: string }[];
  onChange: (v: string) => void;
}) {
  return (
    <div className="flex flex-col gap-1">
      <label className="text-[10px] font-semibold uppercase tracking-wider text-(--text-muted)">
        {label}
      </label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-lg border border-(--border) bg-(--bg-main) px-3 py-1.5 text-xs text-(--text) outline-none focus:border-(--accent)"
      >
        <option value="">All</option>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Page                                                              */
/* ------------------------------------------------------------------ */

interface PageProps {
  params: Promise<{ id: string }>;
}

export default function ScanDetailPage({ params }: PageProps) {
  const { id } = use(params);
  const router = useRouter();
  const { scan, error } = useScanStatus(id);
  const { t, locale } = useTranslation();

  // Findings
  const [findings, setFindings] = useState<FindingData[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsCount, setFindingsCount] = useState(0);
  const [findingsPage, setFindingsPage] = useState(1);
  const [findingsPageSize] = useState(50);
  // OWASP chart
  const [owaspData, setOwaspData] = useState<StackedChartData>([]);
  // Filters
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterTool, setFilterTool] = useState("");
  const [filterOwasp, setFilterOwasp] = useState("");
  // Fix all
  const [fixAllLoading, setFixAllLoading] = useState(false);
  const [fixAllProgress, setFixAllProgress] = useState({ done: 0, total: 0 });
  // Single fix
  const [fixingId, setFixingId] = useState<string | null>(null);
  // AI key check
  const [hasAiKey, setHasAiKey] = useState<boolean | null>(null);

  useEffect(() => {
    api.get("/api/accounts/me/").then((res) => {
      const d = res.data;
      const provider = d.ai_provider || "gemini";
      const keyMap: Record<string, string> = { gemini: d.gemini_api_key, openai: d.openai_api_key, anthropic: d.anthropic_api_key };
      setHasAiKey(!!keyMap[provider]);
    }).catch(() => {});
  }, []);

  const hasFilters = filterSeverity || filterTool || filterOwasp;
  const totalPages = Math.ceil(findingsCount / findingsPageSize);

  const fetchFindings = useCallback(async (page = 1) => {
    setFindingsLoading(true);
    try {
      const params = new URLSearchParams();
      if (filterSeverity) params.set("severity", filterSeverity);
      if (filterTool) params.set("tool", filterTool);
      if (filterOwasp) params.set("owasp", filterOwasp);
      params.set("page", String(page));
      params.set("page_size", String(findingsPageSize));
      const res = await api.get(`/api/scanner/scans/${id}/findings/?${params.toString()}`);
      // Handle both paginated (DRF PageNumberPagination) and plain array responses
      const sortBySeverity = (items: FindingData[]) =>
        [...items].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99));
      if (res.data && typeof res.data === "object" && "results" in res.data) {
        setFindings(sortBySeverity(res.data.results));
        setFindingsCount(res.data.count ?? res.data.results.length);
      } else {
        setFindings(sortBySeverity(res.data));
        setFindingsCount(res.data.length);
      }
    } catch {
      setFindings([]);
      setFindingsCount(0);
    } finally {
      setFindingsLoading(false);
    }
  }, [id, filterSeverity, filterTool, filterOwasp, findingsPageSize]);

  useEffect(() => {
    if (scan?.status === "completed") {
      setFindingsPage(1);
      fetchFindings(1);
      api.get(`/api/scanner/scans/${id}/owasp-chart/`)
        .then((r) => setOwaspData(r.data))
        .catch((err) => { if (err?.response?.status !== 401) console.error("Failed to fetch OWASP chart", err); });
    }
  }, [scan?.status, fetchFindings, id]);

  const checkAiKey = () => {
    if (!hasAiKey) {
      toast.error(t("app.settings.aiKeyRequired"));
      return false;
    }
    return true;
  };

  const fixAllFindings = async () => {
    if (!checkAiKey()) return;
    const unfixed = findings.filter((f) => !f.has_fix && f.status === "open");
    if (unfixed.length === 0) return;
    setFixAllLoading(true);
    setFixAllProgress({ done: 0, total: unfixed.length });
    for (let i = 0; i < unfixed.length; i++) {
      try {
        await api.post(`/api/scanner/findings/${unfixed[i].id}/fix/`, { lang: locale });
      } catch { toast.error(`Failed to generate fix for finding ${i + 1}`); }
      setFixAllProgress({ done: i + 1, total: unfixed.length });
    }
    setFixAllLoading(false);
    fetchFindings(findingsPage);
  };

  const generateFixAndNavigate = async (findingId: string) => {
    if (!checkAiKey()) return;
    setFixingId(findingId);
    try {
      await api.post(`/api/scanner/findings/${findingId}/fix/`, { lang: locale });
      router.push(`/scans/${id}/findings/${findingId}`);
    } catch {
      toast.error("Failed to generate fix");
      setFixingId(null);
    }
  };

  // ----- Error state -----
  if (error) {
    return (
      <div className="flex flex-col gap-6">
        <h1 className="text-2xl font-bold text-(--text)">{t("app.scanDetail.scanStatus")}</h1>
        <div className="rounded-xl border border-red-800 bg-red-900/20 p-8 text-center">
          <span className="material-symbols-outlined text-4xl text-red-400" aria-hidden>error</span>
          <p className="mt-3 text-sm font-medium text-red-300">{error}</p>
          <Link
            href="/dashboard"
            className="mt-4 inline-flex items-center gap-2 rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white hover:bg-(--accent-hover)"
          >
            {t("app.scanDetail.backToDashboard")}
          </Link>
        </div>
      </div>
    );
  }

  // ----- Loading state -----
  if (!scan) {
    return (
      <div className="flex flex-col gap-6">
        <h1 className="text-2xl font-bold text-(--text)">{t("app.scanDetail.scanStatus")}</h1>
        <div className="rounded-xl border border-(--border) bg-(--bg-card) p-8 text-center">
          <span className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-blue-500/30 border-t-blue-400" aria-label="Loading" />
          <p className="mt-3 text-sm text-(--text-muted)">{t("app.scanDetail.loadingScanStatus")}</p>
        </div>
      </div>
    );
  }

  const isTerminal = scan.status === "completed" || scan.status === "failed";
  const name = projectName(scan.source_url, scan.source_type, scan.source_filename);
  const showLanguages = scan.detected_languages && scan.detected_languages.length > 0;
  const expectedAnalyzers = showLanguages ? getExpectedAnalyzers(scan.detected_languages) : [];
  const showAnalyzers = ["scanning", "aggregating", "completed", "failed"].includes(scan.status) && expectedAnalyzers.length > 0;

  // Collect unique tools and owasp categories from findings for filter options
  const toolsInFindings = [...new Set(findings.map((f) => f.tool))].sort();
  const owaspInFindings = [...new Set(findings.map((f) => f.owasp_category))].filter((c) => c !== "UNK").sort();

  return (
    <div className="flex flex-col gap-6">
      <Toaster position="top-right" />
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-4 min-w-0">
          <Link href="/scans" className="text-(--text-muted) hover:text-(--text) transition-colors shrink-0">
            <span className="material-symbols-outlined text-xl" aria-hidden>arrow_back</span>
          </Link>
          <div className="min-w-0">
            <h1 className="text-xl sm:text-2xl font-bold text-(--text) truncate">{name}</h1>
            <p className="text-xs text-(--text-muted) mt-0.5 truncate">
              {scan.source_url || scan.source_type.toUpperCase()} &middot; {new Date(scan.created_at).toLocaleString()}
            </p>
          </div>
          <ScanStatusBadge status={scan.status} />
          {!isTerminal && (
            <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-blue-500/30 border-t-blue-400 shrink-0" aria-label="Polling" />
          )}
        </div>

        {scan.status === "completed" && (
          <div className="flex items-center gap-2 flex-wrap">
            <button
              type="button"
              onClick={async () => {
                try {
                  const res = await api.get(`/api/scanner/scans/${scan.id}/report/pdf/`, { responseType: "blob" });
                  const url = URL.createObjectURL(res.data);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `SecureScan-${name}-${new Date(scan.created_at).toISOString().slice(0, 10)}.pdf`;
                  a.click();
                  URL.revokeObjectURL(url);
                } catch { toast.error("Failed to download PDF report"); }
              }}
              className="inline-flex items-center gap-2 rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white hover:bg-(--accent-hover) transition-colors"
            >
              <span className="material-symbols-outlined text-base" aria-hidden>download</span>
              PDF
            </button>
            <button
              type="button"
              onClick={async () => {
                try {
                  const res = await api.get(`/api/scanner/scans/${scan.id}/report/html/`, { responseType: "blob" });
                  const url = URL.createObjectURL(res.data);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `SecureScan-${name}-${new Date(scan.created_at).toISOString().slice(0, 10)}.html`;
                  a.click();
                  URL.revokeObjectURL(url);
                } catch { toast.error("Failed to download HTML report"); }
              }}
              className="inline-flex items-center gap-2 rounded-lg border border-(--border) bg-(--bg-card) px-4 py-2 text-sm font-medium text-(--text) hover:bg-white/5 transition-colors"
            >
              <span className="material-symbols-outlined text-base" aria-hidden>code</span>
              HTML
            </button>
            <button
              type="button"
              onClick={fixAllFindings}
              disabled={fixAllLoading || findings.filter((f) => !f.has_fix && f.status === "open").length === 0}
              className="inline-flex items-center gap-2 rounded-lg bg-purple-600 px-4 py-2 text-sm font-medium text-white hover:bg-purple-700 transition-colors disabled:opacity-40"
            >
              {fixAllLoading ? (
                <>
                  <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                  {fixAllProgress.done}/{fixAllProgress.total}
                </>
              ) : (
                <>
                  <span className="material-symbols-outlined text-base" aria-hidden>auto_fix_high</span>
                  {t("app.scanDetail.fixAll")}
                </>
              )}
            </button>
          </div>
        )}
      </div>

      {/* Progress bar (non-terminal) */}
      {!isTerminal && (
        <section className="rounded-xl border border-(--border) bg-(--bg-card) p-8">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-white">{t("app.scanDetail.progress")}</h2>
            <p className="text-xs text-white/50">{t("app.scanDetail.updatesAuto")}</p>
          </div>
          <ScanProgressBar status={scan.status} />
        </section>
      )}

      {/* Detected languages + analyzers (non-terminal) */}
      {!isTerminal && (showLanguages || showAnalyzers) && (
        <section className="rounded-xl border border-(--border) bg-(--bg-card) p-6">
          {showLanguages && (
            <div>
              <h2 className="text-sm font-semibold uppercase tracking-wide text-(--text-muted)">{t("app.scanDetail.detectedLanguages")}</h2>
              <div className="mt-3 flex flex-wrap gap-2">
                {scan.detected_languages.filter((l) => l !== "any").map((lang) => (
                  <span key={lang} className="inline-flex items-center rounded-full bg-blue-900/40 px-3 py-1 text-xs font-medium text-blue-300">
                    {LANGUAGE_LABELS[lang] ?? lang}
                  </span>
                ))}
              </div>
            </div>
          )}
          {showAnalyzers && (
            <div className={showLanguages ? "mt-5" : ""}>
              <h2 className="text-sm font-semibold uppercase tracking-wide text-(--text-muted)">{t("app.scanDetail.runningAnalyzers")}</h2>
              <div className="mt-3 flex flex-wrap gap-2">
                {expectedAnalyzers.map((tool) => (
                  <span key={tool} className="inline-flex items-center rounded-full bg-slate-700 px-3 py-1 text-xs font-medium text-slate-300">
                    {ANALYZER_LABELS[tool] ?? tool}
                  </span>
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {/* Failure details */}
      {scan.status === "failed" && (
        <>
          <section className="rounded-xl border border-red-800 bg-red-900/20 p-6">
            <div className="flex items-start gap-3">
              <span className="material-symbols-outlined text-red-400" aria-hidden>error</span>
              <div className="flex-1">
                <h2 className="text-sm font-semibold text-red-300">{t("app.scanDetail.scanFailed")}</h2>
                <p className="mt-1 text-sm text-red-300/80">{scan.error_message || t("app.scanDetail.unexpectedError")}</p>
              </div>
            </div>
            <div className="mt-4">
              <Link
                href="/dashboard"
                className="inline-flex items-center gap-2 rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white hover:bg-(--accent-hover)"
              >
                <span className="material-symbols-outlined text-base" aria-hidden>refresh</span>
                {t("app.scanDetail.retryDashboard")}
              </Link>
            </div>
          </section>
          <section className="rounded-xl border border-(--border) bg-(--bg-card) p-6">
            <ScanProgressBar status={scan.status} />
          </section>
        </>
      )}

      {/* ============================================================= */}
      {/*  COMPLETED — Summary + Findings Table                         */}
      {/* ============================================================= */}
      {scan.status === "completed" && (
        <>
          {/* Summary cards */}
          <section className="rounded-xl border border-(--border) bg-(--bg-card) p-6">
            <div className="flex items-center gap-2 mb-4">
              <span className="material-symbols-outlined text-(--success)" aria-hidden>check_circle</span>
              <h2 className="text-sm font-semibold text-(--success)">{t("app.scanDetail.scanCompleted")}</h2>
              {scan.security_score !== null && (
                <span className="ml-auto text-sm font-bold text-(--text)">
                  {t("app.scanDetail.score")}: <span className={scan.security_score >= 80 ? "text-(--success)" : scan.security_score >= 50 ? "text-(--medium)" : "text-(--critical)"}>{scan.security_score}/100</span>
                </span>
              )}
            </div>
            <div className="grid gap-4 grid-cols-2 sm:grid-cols-3 lg:grid-cols-5">
              {[
                { label: t("app.scanDetail.total"), value: scan.total_findings, color: "text-(--text)" },
                { label: t("app.scanDetail.critical"), value: scan.critical_count, color: "text-(--critical)" },
                { label: t("app.scanDetail.high"), value: scan.high_count, color: "text-(--high)" },
                { label: t("app.scanDetail.medium"), value: scan.medium_count, color: "text-(--medium)" },
                { label: t("app.scanDetail.low"), value: scan.low_count, color: "text-(--low)" },
              ].map(({ label, value, color }) => (
                <div key={label} className="rounded-lg border border-(--border) bg-(--bg-main) px-4 py-3 text-center">
                  <p className={`text-2xl font-bold ${color}`}>{value}</p>
                  <p className="mt-1 text-xs text-(--text-muted)">{label}</p>
                </div>
              ))}
            </div>
          </section>

          {/* OWASP Distribution chart */}
          {owaspData.length > 0 && (
            <section className="rounded-xl border border-(--border) bg-(--bg-card) p-6">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-(--text-muted) mb-5">
                OWASP Top 10 — Distribution
              </h2>
              <SeverityChart stackedData={owaspData} />
            </section>
          )}

          {/* Detected Vulnerabilities heading + filters */}
          <section className="rounded-xl border border-(--border) bg-(--bg-card) overflow-hidden">
            <div className="border-b border-(--border) px-6 py-4">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <h2 className="text-lg font-semibold text-(--text)">{t("app.scanDetail.detectedVulnerabilities")}</h2>
                <div className="flex items-end gap-3 flex-wrap">
                  <FilterDropdown
                    label={t("app.scanDetail.severity")}
                    value={filterSeverity}
                    onChange={setFilterSeverity}
                    options={[
                      { value: "critical", label: "Critical" },
                      { value: "high", label: "High" },
                      { value: "medium", label: "Medium" },
                      { value: "low", label: "Low" },
                      { value: "info", label: "Info" },
                    ]}
                  />
                  <FilterDropdown
                    label={t("app.scanDetail.tool")}
                    value={filterTool}
                    onChange={setFilterTool}
                    options={toolsInFindings.map((t) => ({ value: t, label: TOOL_LABELS[t] ?? t }))}
                  />
                  <FilterDropdown
                    label={t("app.scanDetail.owaspLabel")}
                    value={filterOwasp}
                    onChange={setFilterOwasp}
                    options={owaspInFindings.map((c) => ({ value: c, label: OWASP_LABELS[c] ?? c }))}
                  />
                  {hasFilters && (
                    <button
                      type="button"
                      onClick={() => { setFilterSeverity(""); setFilterTool(""); setFilterOwasp(""); }}
                      className="text-xs text-(--accent) hover:underline pb-1.5"
                    >
                      {t("app.scanDetail.clearAllFilters")}
                    </button>
                  )}
                </div>
              </div>
            </div>

            {/* Findings table */}
            <div className="overflow-auto">
              {findingsLoading ? (
                <div className="flex items-center justify-center py-12">
                  <span className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-blue-500/30 border-t-blue-400" />
                  <span className="ml-3 text-sm text-(--text-muted)">{t("app.scanDetail.loadingFindings")}</span>
                </div>
              ) : findings.length === 0 ? (
                <div className="py-12 text-center">
                  <span className="material-symbols-outlined text-4xl text-(--success)" aria-hidden>verified</span>
                  <p className="mt-2 text-sm text-(--text-muted)">
                    {hasFilters ? t("app.scanDetail.noFilterMatch") : t("app.scanDetail.noVulnerabilities")}
                  </p>
                </div>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-(--border) text-left text-[10px] font-semibold uppercase tracking-wider text-(--text-muted)">
                      <th className="px-4 sm:px-6 py-3">{t("app.scanDetail.severity")}</th>
                      <th className="px-4 sm:px-6 py-3">{t("app.scanDetail.vulnerability")}</th>
                      <th className="hidden md:table-cell px-6 py-3">{t("app.scanDetail.tool")}</th>
                      <th className="hidden lg:table-cell px-6 py-3">{t("app.scanDetail.filePath")}</th>
                      <th className="px-4 py-3">Fix</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((f) => (
                      <tr key={f.id} className={`border-b border-(--border) transition-colors hover:bg-white/5 ${f.has_fix ? "bg-green-500/5" : ""}`}>
                        <td className="py-3 pl-4 sm:pl-6">
                          <Link href={`/scans/${id}/findings/${f.id}`} className="block">
                            <SeverityBadge severity={f.severity} />
                          </Link>
                        </td>
                        <td className="px-4 sm:px-6 py-3">
                          <Link href={`/scans/${id}/findings/${f.id}`} className="block">
                            <p className="font-medium text-(--text)">{f.title}</p>
                            <p className="mt-0.5 text-xs text-(--text-muted)">{OWASP_LABELS[f.owasp_category] ?? f.owasp_category}</p>
                          </Link>
                        </td>
                        <td className="hidden md:table-cell px-6 py-3">
                          <Link href={`/scans/${id}/findings/${f.id}`} className="block text-(--text-muted)">
                            {TOOL_LABELS[f.tool] ?? f.tool}
                          </Link>
                        </td>
                        <td className="hidden lg:table-cell px-6 py-3">
                          <Link href={`/scans/${id}/findings/${f.id}`} className="block">
                            <span className="font-mono text-xs text-(--text-muted) break-all">
                              {f.file_path}
                              {f.line_start && <span className="text-(--accent)">:{f.line_start}</span>}
                            </span>
                          </Link>
                        </td>
                        <td className="px-4 py-3">
                          {f.has_fix ? (
                            <Link
                              href={`/scans/${id}/findings/${f.id}`}
                              className="inline-flex items-center gap-1 rounded-full bg-green-500/20 px-2.5 py-1 text-[11px] font-semibold text-green-400 hover:bg-green-500/30 transition-colors"
                            >
                              <span className="material-symbols-outlined text-xs" aria-hidden>visibility</span>
                              {t("app.scanDetail.viewFix") || "Voir le fix"}
                            </Link>
                          ) : (
                            <button
                              type="button"
                              disabled={fixingId === f.id}
                              onClick={(e) => { e.preventDefault(); generateFixAndNavigate(f.id); }}
                              className="inline-flex items-center gap-1 rounded-full bg-purple-600/20 px-2.5 py-1 text-[11px] font-semibold text-purple-400 hover:bg-purple-600/30 transition-colors disabled:opacity-50"
                            >
                              {fixingId === f.id ? (
                                <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-purple-400/30 border-t-purple-400" />
                              ) : (
                                <span className="material-symbols-outlined text-xs" aria-hidden>auto_fix_high</span>
                              )}
                              {fixingId === f.id ? "..." : (t("app.scanDetail.generateFix") || "Générer un fix")}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
            {/* Pagination controls */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between border-t border-(--border) px-6 py-3">
                <p className="text-xs text-(--text-muted)">
                  Page {findingsPage} / {totalPages} &mdash; {findingsCount} findings
                </p>
                <div className="flex gap-2">
                  <button
                    type="button"
                    disabled={findingsPage <= 1}
                    onClick={() => { const p = findingsPage - 1; setFindingsPage(p); fetchFindings(p); }}
                    className="rounded-lg border border-(--border) px-3 py-1 text-xs text-(--text) disabled:opacity-40 hover:bg-white/5 transition-colors"
                  >
                    ← Prev
                  </button>
                  <button
                    type="button"
                    disabled={findingsPage >= totalPages}
                    onClick={() => { const p = findingsPage + 1; setFindingsPage(p); fetchFindings(p); }}
                    className="rounded-lg border border-(--border) px-3 py-1 text-xs text-(--text) disabled:opacity-40 hover:bg-white/5 transition-colors"
                  >
                    Next →
                  </button>
                </div>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}
