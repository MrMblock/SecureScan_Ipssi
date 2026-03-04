"use client";

import { useEffect, useState } from "react";
import api from "@/lib/api";
import FindingFixPanel from "@/components/scanner/FindingFixPanel";
import toast from "react-hot-toast";
import { useTranslation } from "@/i18n";

interface Scan {
  id: string;
  source_url: string;
  source_type: string;
  status: string;
  created_at: string;
  total_findings: number;
}

interface Finding {
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

const FINDING_STATUS_OPTIONS = [
  { value: "open", label: "Open", color: "bg-blue-500/20 text-blue-300" },
  { value: "false_positive", label: "False Positive", color: "bg-yellow-500/20 text-yellow-300" },
  { value: "accepted_risk", label: "Accepted Risk", color: "bg-orange-500/20 text-orange-300" },
  { value: "fixed", label: "Fixed", color: "bg-green-500/20 text-green-300" },
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-(--critical) text-white",
  high: "bg-(--high) text-white",
  medium: "bg-(--medium) text-black",
  low: "bg-(--low) text-white",
  info: "bg-slate-600 text-white",
};

const OWASP_TOP10: { code: string; name: string }[] = [
  { code: "A01", name: "Broken Access Control" },
  { code: "A02", name: "Security Misconfiguration" },
  { code: "A03", name: "Software Supply Chain Failures" },
  { code: "A04", name: "Cryptographic Failures" },
  { code: "A05", name: "Injection" },
  { code: "A06", name: "Insecure Design" },
  { code: "A07", name: "Authentication Failures" },
  { code: "A08", name: "Software or Data Integrity Failures" },
  { code: "A09", name: "Security Logging & Alerting Failures" },
  { code: "A10", name: "Mishandling of Exceptional Conditions" },
];

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
  trufflehog: "TruffleHog",
  eslint: "ESLint",
  npm_audit: "npm audit",
};

export default function VulnerabilitiesPage() {
  const { t } = useTranslation();
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScan, setSelectedScan] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingFindings, setLoadingFindings] = useState(false);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  const [toolFilter, setToolFilter] = useState<string | null>(null);
  const [owaspFilter, setOwaspFilter] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string | null>(null);

  // Detail panel
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  useEffect(() => {
    api
      .get("/api/scanner/scans/")
      .then((res) => {
        const completed = res.data.filter((s: Scan) => s.status === "completed");
        setScans(completed);
        if (completed.length > 0) {
          setSelectedScan(completed[0].id);
        }
      })
      .catch((err) => { if (err?.response?.status !== 401) console.error("Failed to fetch scans", err); })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!selectedScan) return;
    setLoadingFindings(true);
    setSelectedFinding(null);
    api
      .get(`/api/scanner/scans/${selectedScan}/findings/?show_all=true`)
      .then((res) => setFindings(res.data))
      .catch(() => setFindings([]))
      .finally(() => setLoadingFindings(false));
  }, [selectedScan]);

  const filtered = findings
    .filter((f) => {
      if (severityFilter && f.severity !== severityFilter) return false;
      if (toolFilter && f.tool !== toolFilter) return false;
      if (owaspFilter && f.owasp_category !== owaspFilter) return false;
      if (statusFilter && f.status !== statusFilter) return false;
      return true;
    })
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99));

  const updateFindingStatus = async (findingId: string, newStatus: string) => {
    try {
      const res = await api.patch(`/api/scanner/findings/${findingId}/status/`, { status: newStatus });
      setFindings((prev) => prev.map((f) => f.id === findingId ? { ...f, status: res.data.status } : f));
      if (selectedFinding?.id === findingId) {
        setSelectedFinding((prev) => prev ? { ...prev, status: res.data.status } : prev);
      }
    } catch { toast.error("Failed to update finding status"); }
  };

  // Collect unique tool values for filter chips
  const tools = [...new Set(findings.map((f) => f.tool))];

  // OWASP counts from findings
  const owaspCounts: Record<string, { total: number; critical: number; high: number; medium: number; low: number }> = {};
  for (const f of findings) {
    if (!owaspCounts[f.owasp_category]) {
      owaspCounts[f.owasp_category] = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
    }
    owaspCounts[f.owasp_category].total++;
    if (f.severity in owaspCounts[f.owasp_category]) {
      owaspCounts[f.owasp_category][f.severity as "critical" | "high" | "medium" | "low"]++;
    }
  }
  const maxOwaspCount = Math.max(1, ...Object.values(owaspCounts).map((c) => c.total));

  if (loading) {
    return (
      <div className="flex flex-col gap-6">
        <h1 className="text-2xl font-bold text-(--text)">{t("app.vulnerabilities.title")}</h1>
        <div className="rounded-xl border border-(--border) bg-(--bg-card) p-8 text-center">
          <span className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-blue-500/30 border-t-blue-400" />
        </div>
      </div>
    );
  }

  if (scans.length === 0) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-(--text)">{t("app.vulnerabilities.title")}</h1>
        <div className="rounded-xl border border-(--border) bg-(--bg-card) p-8 text-center text-(--text-muted)">
          <p>{t("app.vulnerabilities.noCompletedScans")}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-(--text)">{t("app.vulnerabilities.title")}</h1>

      {/* Scan selector */}
      <div className="flex items-center gap-3">
        <label className="text-sm font-medium text-(--text-muted)">{t("app.vulnerabilities.scanLabel")}</label>
        <select
          value={selectedScan ?? ""}
          onChange={(e) => setSelectedScan(e.target.value)}
          className="rounded-lg border border-(--border) bg-(--bg-card) px-3 py-1.5 text-sm text-(--text)"
        >
          {scans.map((s) => (
            <option key={s.id} value={s.id}>
              {s.source_url
                ? s.source_url.replace(/\.git$/, "").split("/").pop()
                : s.source_type.toUpperCase()}{" "}
              — {new Date(s.created_at).toLocaleDateString()} ({s.total_findings} findings)
            </option>
          ))}
        </select>
      </div>

      {/* OWASP Top 10 2025 section */}
      {findings.length > 0 && (
        <section className="rounded-xl border border-(--border) bg-(--bg-card) p-6">
          <h2 className="text-lg font-semibold text-(--text) flex items-center gap-2">
            <span className="material-symbols-outlined text-xl text-(--accent)" aria-hidden>
              shield
            </span>
            OWASP Top 10 — 2025
          </h2>
          <div className="mt-4 space-y-2">
            {OWASP_TOP10.map(({ code, name }) => {
              const counts = owaspCounts[code] || { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
              const isActive = owaspFilter === code;
              const barWidth = (counts.total / maxOwaspCount) * 100;

              return (
                <button
                  key={code}
                  type="button"
                  onClick={() => setOwaspFilter(isActive ? null : code)}
                  className={`w-full text-left rounded-lg p-3 transition-colors ${
                    isActive
                      ? "bg-(--accent)/15 ring-1 ring-(--accent)"
                      : "hover:bg-(--bg-main)"
                  }`}
                >
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex items-center gap-3 min-w-0">
                      <span className={`shrink-0 w-10 text-center rounded px-1.5 py-0.5 text-xs font-bold ${
                        counts.total > 0 ? "bg-(--accent)/20 text-(--accent)" : "bg-(--text-muted)/10 text-(--text-muted)"
                      }`}>
                        {code}
                      </span>
                      <span className={`text-sm truncate ${counts.total > 0 ? "text-(--text)" : "text-(--text-muted)"}`}>
                        {name}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      {counts.critical > 0 && (
                        <span className="rounded bg-(--critical)/20 px-1.5 py-0.5 text-xs font-medium text-(--critical)">
                          {counts.critical} critical
                        </span>
                      )}
                      {counts.high > 0 && (
                        <span className="rounded bg-(--high)/20 px-1.5 py-0.5 text-xs font-medium text-(--high)">
                          {counts.high} high
                        </span>
                      )}
                      <span className={`text-sm font-semibold ${counts.total > 0 ? "text-(--text)" : "text-(--text-muted)"}`}>
                        {counts.total}
                      </span>
                    </div>
                  </div>
                  {/* Stacked severity bar */}
                  {counts.total > 0 && (
                    <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-white/5">
                      <div className="flex h-full" style={{ width: `${barWidth}%` }}>
                        {counts.critical > 0 && (
                          <div className="h-full bg-(--critical)" style={{ width: `${(counts.critical / counts.total) * 100}%` }} />
                        )}
                        {counts.high > 0 && (
                          <div className="h-full bg-(--high)" style={{ width: `${(counts.high / counts.total) * 100}%` }} />
                        )}
                        {counts.medium > 0 && (
                          <div className="h-full bg-(--medium)" style={{ width: `${(counts.medium / counts.total) * 100}%` }} />
                        )}
                        {counts.low > 0 && (
                          <div className="h-full bg-(--low)" style={{ width: `${(counts.low / counts.total) * 100}%` }} />
                        )}
                      </div>
                    </div>
                  )}
                </button>
              );
            })}
          </div>
          {/* Legend */}
          <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-(--text-muted)">
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-(--critical)" /> Critical</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-(--high)" /> High</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-(--medium)" /> Medium</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-(--low)" /> Low</span>
            {owaspFilter && (
              <button
                type="button"
                onClick={() => setOwaspFilter(null)}
                className="ml-auto text-xs text-(--accent) hover:underline"
              >
                {t("app.vulnerabilities.clearFilter")}
              </button>
            )}
          </div>
        </section>
      )}

      {/* Filters: Severity + Tool */}
      <div className="flex flex-wrap gap-4">
        {/* Severity filter */}
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-(--text-muted)">{t("app.vulnerabilities.severityLabel")}</span>
          {[null, "critical", "high", "medium", "low"].map((sev) => (
            <button
              key={sev ?? "all"}
              type="button"
              onClick={() => setSeverityFilter(sev)}
              className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                severityFilter === sev
                  ? "bg-(--accent) text-white"
                  : "bg-(--bg-card) text-(--text-muted) hover:text-(--text)"
              }`}
            >
              {sev ? sev.charAt(0).toUpperCase() + sev.slice(1) : t("app.vulnerabilities.all")}
            </button>
          ))}
        </div>

        {/* Tool filter */}
        {tools.length > 1 && (
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-(--text-muted)">{t("app.vulnerabilities.toolLabel")}</span>
            <button
              type="button"
              onClick={() => setToolFilter(null)}
              className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                !toolFilter
                  ? "bg-(--accent) text-white"
                  : "bg-(--bg-card) text-(--text-muted) hover:text-(--text)"
              }`}
            >
              {t("app.vulnerabilities.all")}
            </button>
            {tools.map((tool) => (
              <button
                key={tool}
                type="button"
                onClick={() => setToolFilter(tool)}
                className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                  toolFilter === tool
                    ? "bg-(--accent) text-white"
                    : "bg-(--bg-card) text-(--text-muted) hover:text-(--text)"
                }`}
              >
                {TOOL_LABELS[tool] ?? tool}
              </button>
            ))}
          </div>
        )}

        {/* Status filter */}
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-(--text-muted)">Status:</span>
          <button
            type="button"
            onClick={() => setStatusFilter(null)}
            className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${
              !statusFilter ? "bg-(--accent) text-white" : "bg-(--bg-card) text-(--text-muted) hover:text-(--text)"
            }`}
          >
            {t("app.vulnerabilities.all")}
          </button>
          {FINDING_STATUS_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              type="button"
              onClick={() => setStatusFilter(opt.value)}
              className={`rounded-full px-3 py-1 text-xs font-medium transition-colors ${
                statusFilter === opt.value ? "bg-(--accent) text-white" : "bg-(--bg-card) text-(--text-muted) hover:text-(--text)"
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main content: findings list + detail panel */}
      <div className="grid gap-6 lg:grid-cols-5">
        {/* Findings list */}
        <div className="lg:col-span-3 space-y-2">
          {loadingFindings ? (
            <div className="rounded-xl border border-(--border) bg-(--bg-card) p-8 text-center">
              <span className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-blue-500/30 border-t-blue-400" />
            </div>
          ) : filtered.length === 0 ? (
            <div className="rounded-xl border border-(--border) bg-(--bg-card) p-8 text-center text-(--text-muted)">
              {findings.length === 0
                ? t("app.vulnerabilities.noFindings")
                : t("app.vulnerabilities.noFilterMatch")}
            </div>
          ) : (
            filtered.map((f) => (
              <button
                key={f.id}
                type="button"
                onClick={() => setSelectedFinding(f)}
                className={`w-full text-left rounded-lg border p-4 transition-colors ${
                  selectedFinding?.id === f.id
                    ? "border-(--accent) bg-(--accent)/10"
                    : "border-(--border) bg-(--bg-card) hover:border-(--accent)/50"
                }`}
              >
                <div className="flex items-center gap-2">
                  <span
                    className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${
                      SEVERITY_COLORS[f.severity] ?? SEVERITY_COLORS.info
                    }`}
                  >
                    {f.severity.toUpperCase()}
                  </span>
                  <span className="rounded bg-(--text-muted)/20 px-2 py-0.5 text-xs text-(--text-muted)">
                    {f.owasp_category}
                  </span>
                  <span className="rounded bg-(--text-muted)/20 px-2 py-0.5 text-xs text-(--text-muted)">
                    {TOOL_LABELS[f.tool] ?? f.tool}
                  </span>
                  {f.status !== "open" && (
                    <span className={`rounded px-2 py-0.5 text-xs font-medium ${
                      FINDING_STATUS_OPTIONS.find((o) => o.value === f.status)?.color ?? ""
                    }`}>
                      {FINDING_STATUS_OPTIONS.find((o) => o.value === f.status)?.label ?? f.status}
                    </span>
                  )}
                  {f.has_fix && (
                    <span className="rounded bg-green-500/20 px-2 py-0.5 text-xs text-green-400">
                      AI Fix
                    </span>
                  )}
                  {f.fix_pr_url && (
                    <span className="rounded bg-blue-500/20 px-2 py-0.5 text-xs text-blue-400">
                      PR
                    </span>
                  )}
                </div>
                <p className="mt-1.5 font-medium text-(--text) text-sm">{f.title}</p>
                <p className="mt-1 text-xs text-(--text-muted)">
                  {f.file_path}
                  {f.line_start && `:${f.line_start}`}
                </p>
              </button>
            ))
          )}
        </div>

        {/* Detail panel */}
        <div className="lg:col-span-2">
          {selectedFinding ? (
            <div className="sticky top-6 rounded-xl border border-(--border) bg-(--bg-card) p-5 space-y-4">
              <div className="flex items-center gap-2">
                <span
                  className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${
                    SEVERITY_COLORS[selectedFinding.severity] ?? SEVERITY_COLORS.info
                  }`}
                >
                  {selectedFinding.severity.toUpperCase()}
                </span>
                <span className="text-xs text-(--text-muted)">
                  {selectedFinding.owasp_category} — {
                    OWASP_TOP10.find((o) => o.code === selectedFinding.owasp_category)?.name ?? ""
                  }
                </span>
              </div>
              <h3 className="text-lg font-semibold text-(--text)">{selectedFinding.title}</h3>
              {selectedFinding.description && (
                <p className="text-sm text-(--text-muted)">{selectedFinding.description}</p>
              )}
              {/* Status change */}
              <div className="flex items-center gap-2">
                <span className="text-xs font-medium text-(--text-muted)">Status:</span>
                <select
                  value={selectedFinding.status}
                  onChange={(e) => updateFindingStatus(selectedFinding.id, e.target.value)}
                  className={`rounded-lg border border-(--border) px-3 py-1.5 text-xs font-medium outline-none ${
                    FINDING_STATUS_OPTIONS.find((o) => o.value === selectedFinding.status)?.color ?? "bg-(--bg-card) text-(--text)"
                  }`}
                >
                  {FINDING_STATUS_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </div>
              <p className="text-xs text-(--text-muted)">
                <span className="material-symbols-outlined text-sm align-middle" aria-hidden>
                  description
                </span>{" "}
                {selectedFinding.file_path}
                {selectedFinding.line_start && `:${selectedFinding.line_start}`}
                {selectedFinding.rule_id && (
                  <span className="ml-2 opacity-60">{selectedFinding.rule_id}</span>
                )}
              </p>

              {/* Original code */}
              {selectedFinding.code_snippet && (
                <pre className="max-h-32 overflow-auto rounded bg-black/30 p-3 text-xs text-(--text-muted)">
                  {selectedFinding.code_snippet}
                </pre>
              )}

              {/* AI Remediation */}
              <div>
                <h4 className="text-sm font-semibold text-(--text) flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-purple-400 text-lg" aria-hidden>
                    auto_fix_high
                  </span>
                  {t("app.vulnerabilities.aiRemediation")}
                </h4>
                <FindingFixPanel
                  findingId={selectedFinding.id}
                  originalCode={selectedFinding.code_snippet}
                  existingPrUrl={selectedFinding.fix_pr_url}
                  initialFix={
                    selectedFinding.has_fix
                      ? {
                          fixed_code: selectedFinding.fixed_code,
                          fix_explanation: selectedFinding.fix_explanation,
                          original_code: selectedFinding.code_snippet,
                          file_path: selectedFinding.file_path,
                          line_start: selectedFinding.line_start,
                          cached: true,
                        }
                      : null
                  }
                />
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-(--border) bg-(--bg-card) p-8 text-center text-(--text-muted)">
              <span className="material-symbols-outlined text-4xl mb-2" aria-hidden>
                touch_app
              </span>
              <p className="text-sm">{t("app.vulnerabilities.selectVulnerability")}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
