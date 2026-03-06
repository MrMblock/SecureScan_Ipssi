"use client";

import { use, useEffect, useRef, useState } from "react";
import Link from "next/link";
import axios from "axios";
import toast, { Toaster } from "react-hot-toast";
import api from "@/lib/api";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { vscDarkPlus } from "react-syntax-highlighter/dist/esm/styles/prism";
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

const FINDING_STATUS_OPTIONS = [
  { value: "open", label: "Open", color: "bg-blue-500/20 text-blue-300" },
  { value: "false_positive", label: "False Positive", color: "bg-yellow-500/20 text-yellow-300" },
  { value: "accepted_risk", label: "Accepted Risk", color: "bg-orange-500/20 text-orange-300" },
  { value: "fixed", label: "Fixed", color: "bg-green-500/20 text-green-300" },
];

interface ScanMeta {
  id: string;
  source_url: string;
  source_type: string;
  source_filename?: string;
  created_at: string;
}

/* ------------------------------------------------------------------ */
/*  Constants                                                         */
/* ------------------------------------------------------------------ */

const OWASP_LABELS: Record<string, string> = {
  A01: "Broken Access Control",
  A02: "Security Misconfiguration",
  A03: "Software Supply Chain Failures",
  A04: "Cryptographic Failures",
  A05: "Injection",
  A06: "Insecure Design",
  A07: "Authentication Failures",
  A08: "Software or Data Integrity Failures",
  A09: "Security Logging & Alerting Failures",
  A10: "Mishandling of Exceptional Conditions",
};

const OWASP_LINKS: Record<string, string> = {
  A01: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
  A02: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
  A03: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
  A04: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
  A05: "https://owasp.org/Top10/A03_2021-Injection/",
  A06: "https://owasp.org/Top10/A04_2021-Insecure_Design/",
  A07: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
  A08: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
  A09: "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
  A10: "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
};

const SEVERITY_CONFIG: Record<string, { label: string; color: string; bg: string }> = {
  critical: { label: "Critical", color: "text-red-400", bg: "bg-red-500/20" },
  high: { label: "High", color: "text-orange-400", bg: "bg-orange-500/20" },
  medium: { label: "Medium", color: "text-yellow-400", bg: "bg-yellow-500/20" },
  low: { label: "Low", color: "text-blue-400", bg: "bg-blue-500/20" },
  info: { label: "Info", color: "text-slate-400", bg: "bg-slate-500/20" },
};

const TOOL_LABELS: Record<string, string> = {
  semgrep: "Semgrep",
  bandit: "Bandit",
  eslint: "ESLint",
  npm_audit: "npm audit",
  trufflehog: "TruffleHog",
};

function projectName(url: string, type: string, sourceFilename?: string): string {
  if (type === "dast") {
    return sourceFilename || url || "DAST Scan";
  }
  if (url) {
    const parts = url.replace(/\.git$/, "").split("/");
    return parts[parts.length - 1] || "Unknown";
  }
  return sourceFilename || (type === "zip" ? "ZIP Upload" : "File Upload");
}

/* ------------------------------------------------------------------ */
/*  File extension → Prism language                                     */
/* ------------------------------------------------------------------ */

const EXT_TO_PRISM: Record<string, string> = {
  ".py": "python", ".pyw": "python", ".pyi": "python",
  ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".jsx": "jsx", ".tsx": "tsx",
  ".ts": "typescript",
  ".html": "html", ".htm": "html",
  ".css": "css",
  ".json": "json",
  ".yaml": "yaml", ".yml": "yaml",
  ".go": "go",
  ".rs": "rust",
  ".c": "c", ".h": "c",
  ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
  ".swift": "swift",
  ".kt": "kotlin", ".kts": "kotlin",
  ".sql": "sql",
  ".md": "markdown",
  ".xml": "xml",
  ".svg": "xml",
};

function detectPrismLang(filePath: string): string {
  const dot = filePath.lastIndexOf(".");
  if (dot === -1) return "text";
  return EXT_TO_PRISM[filePath.slice(dot).toLowerCase()] ?? "text";
}

/* ------------------------------------------------------------------ */
/*  CodeViewer — full source with syntax highlighting                   */
/* ------------------------------------------------------------------ */

function CodeViewer({
  code,
  highlightStart,
  highlightEnd,
  highlightColor,
  highlightLines,
  language,
}: {
  code: string;
  highlightStart?: number | null;
  highlightEnd?: number | null;
  highlightColor: "red" | "green";
  highlightLines?: Set<number> | null;
  language: string;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const target = highlightStart ?? (highlightLines?.size ? Math.min(...highlightLines) : null);
    if (target && scrollRef.current) {
      const el = scrollRef.current.querySelector(`[data-line="${target}"]`);
      if (el) {
        requestAnimationFrame(() =>
          el.scrollIntoView({ block: "center", behavior: "smooth" }),
        );
      }
    }
  }, [highlightStart, highlightLines, code]);

  return (
    <div ref={scrollRef} className="overflow-auto max-h-[520px]">
      <SyntaxHighlighter
        language={language === "text" ? "plaintext" : language}
        style={vscDarkPlus}
        showLineNumbers
        wrapLines
        lineNumberStyle={{
          color: "#4b5563",
          minWidth: "3.5em",
          paddingRight: "1em",
          userSelect: "none" as const,
          fontSize: "0.7rem",
        }}
        lineProps={(lineNumber: number) => {
          const isHL = highlightLines
            ? highlightLines.has(lineNumber)
            : highlightStart != null &&
              highlightEnd != null &&
              lineNumber >= highlightStart &&
              lineNumber <= highlightEnd;
          return {
            "data-line": lineNumber as any,
            style: {
              display: "block" as const,
              ...(isHL
                ? {
                    backgroundColor:
                      highlightColor === "red"
                        ? "rgba(239,68,68,0.18)"
                        : "rgba(34,197,94,0.18)",
                    borderLeft: `3px solid ${
                      highlightColor === "red" ? "#ef4444" : "#22c55e"
                    }`,
                  }
                : {}),
            },
          };
        }}
        customStyle={{
          margin: 0,
          padding: "12px 0",
          background: "transparent",
          fontSize: "0.75rem",
          lineHeight: "1.6",
          fontFamily:
            '"Cascadia Code", "Fira Code", "JetBrains Mono", "SFMono-Regular", Menlo, Consolas, monospace',
        }}
        codeTagProps={{ style: { fontFamily: "inherit" } }}
      >
        {code}
      </SyntaxHighlighter>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Merge fix into full source                                         */
/* ------------------------------------------------------------------ */

function getMergedCode(
  fullSource: string,
  fixedCode: string,
  lineStart: number,
  lineEnd: number,
): { code: string; fixStart: number; fixEnd: number } {
  const sourceLines = fullSource.split("\n");
  const fixLines = fixedCode.split("\n");
  const before = sourceLines.slice(0, lineStart - 1);
  const after = sourceLines.slice(lineEnd);
  const merged = [...before, ...fixLines, ...after];
  return {
    code: merged.join("\n"),
    fixStart: lineStart,
    fixEnd: lineStart + fixLines.length - 1,
  };
}

/* ------------------------------------------------------------------ */
/*  Page                                                              */
/* ------------------------------------------------------------------ */

interface PageProps {
  params: Promise<{ id: string; findingId: string }>;
}

export default function FindingDetailPage({ params }: PageProps) {
  const { id: scanId, findingId } = use(params);
  const { t, locale } = useTranslation();

  const [finding, setFinding] = useState<FindingData | null>(null);
  const [scanMeta, setScanMeta] = useState<ScanMeta | null>(null);
  const [fullSource, setFullSource] = useState<string | null>(null);
  const [otherOccurrences, setOtherOccurrences] = useState<FindingData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Fix
  const [fixLoading, setFixLoading] = useState(false);
  const [fixError, setFixError] = useState<string | null>(null);
  const [isPatternFix, setIsPatternFix] = useState(false);
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

  // PR
  const [prUrl, setPrUrl] = useState("");
  const [applyingFix, setApplyingFix] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const [findingRes, scanRes] = await Promise.all([
          api.get(`/api/scanner/findings/${findingId}/`),
          api.get(`/api/scanner/scans/${scanId}/`),
        ]);
        const target: FindingData = findingRes.data;
        setFinding(target);
        setScanMeta(scanRes.data);
        if (target.fix_pr_url) setPrUrl(target.fix_pr_url);

        // Fetch other occurrences in the same file
        try {
          const findingsRes = await api.get(`/api/scanner/scans/${scanId}/findings/?page_size=200`);
          const allFindings: FindingData[] = findingsRes.data?.results ?? findingsRes.data;
          setOtherOccurrences(
            allFindings.filter(
              (f) => f.id !== findingId && f.file_path === target.file_path,
            ),
          );
        } catch { /* ignore */ }

        // Fetch full source file
        try {
          const sourceRes = await api.get(
            `/api/scanner/scans/${scanId}/source/`,
            { params: { path: target.file_path } },
          );
          setFullSource(sourceRes.data.content);
        } catch {
          // Fallback to snippet
        }
      } catch {
        setError("Failed to load finding details.");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [scanId, findingId]);

  const requestFix = async () => {
    if (!finding) return;
    if (!hasAiKey) {
      toast.error(t("app.settings.aiKeyRequired"));
      return;
    }
    setFixLoading(true);
    setFixError(null);
    try {
      const res = await api.post(`/api/scanner/findings/${findingId}/fix/`, { lang: locale });
      setFinding({
        ...finding,
        has_fix: true,
        fixed_code: res.data.fixed_code,
        fix_explanation: res.data.fix_explanation,
      });
      setIsPatternFix(!!res.data.pattern_id);
    } catch (err: unknown) {
      setFixError(
        axios.isAxiosError(err) && err.response?.data?.detail
          ? err.response.data.detail
          : "Failed to generate fix.",
      );
    } finally {
      setFixLoading(false);
    }
  };

  const handleApplyFix = async () => {
    setApplyingFix(true);
    setApplyError(null);
    try {
      const res = await api.post(`/api/scanner/findings/${findingId}/apply/`);
      setPrUrl(res.data.pr_url);
    } catch (err: unknown) {
      setApplyError(
        axios.isAxiosError(err) && err.response?.data?.detail
          ? err.response.data.detail
          : "Failed to create PR.",
      );
    } finally {
      setApplyingFix(false);
    }
  };

  const downloadPdf = async () => {
    if (!scanMeta) return;
    try {
      const res = await api.get(
        `/api/scanner/scans/${scanId}/report/pdf/`,
        { responseType: "blob" },
      );
      const url = URL.createObjectURL(res.data);
      const a = document.createElement("a");
      a.href = url;
      const pName = projectName(scanMeta.source_url, scanMeta.source_type, scanMeta.source_filename);
      a.download = `SecureScan-${pName}-${new Date(scanMeta.created_at).toISOString().slice(0, 10)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      /* ignore */
    }
  };

  const downloadHtml = async () => {
    if (!scanMeta) return;
    try {
      const res = await api.get(
        `/api/scanner/scans/${scanId}/report/html/`,
        { responseType: "blob" },
      );
      const url = URL.createObjectURL(res.data);
      const a = document.createElement("a");
      a.href = url;
      const pName = projectName(scanMeta.source_url, scanMeta.source_type, scanMeta.source_filename);
      a.download = `SecureScan-${pName}-${new Date(scanMeta.created_at).toISOString().slice(0, 10)}.html`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      /* ignore */
    }
  };

  const updateStatus = async (newStatus: string) => {
    if (!finding) return;
    try {
      const res = await api.patch(`/api/scanner/findings/${findingId}/status/`, { status: newStatus });
      setFinding({ ...finding, status: res.data.status });
    } catch {
      /* ignore */
    }
  };

  /* ---------- Loading / Error ---------- */

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <span className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-blue-500/30 border-t-blue-400" />
        <p className="mt-3 text-sm text-(--text-muted)">
          {t("app.findingDetail.loadingDetails")}
        </p>
      </div>
    );
  }

  if (error || !finding) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <span className="material-symbols-outlined text-4xl text-red-400" aria-hidden>
          error
        </span>
        <p className="mt-3 text-sm text-red-300">{error || t("app.findingDetail.findingNotFound")}</p>
        <Link
          href={`/scans/${scanId}`}
          className="mt-4 inline-flex items-center gap-2 rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white hover:bg-(--accent-hover)"
        >
          {t("app.findingDetail.backToScan")}
        </Link>
      </div>
    );
  }

  const sev = SEVERITY_CONFIG[finding.severity] ?? SEVERITY_CONFIG.info;
  const pName = scanMeta
    ? projectName(scanMeta.source_url, scanMeta.source_type, scanMeta.source_filename)
    : "Scan";

  /* ---------- Build code for each tab ---------- */
  const prismLang = detectPrismLang(finding.file_path);
  // If we have the full source but no line info, fall back to the snippet
  // so the user still sees highlighted vulnerable code instead of a plain file.
  const hasLineInfo = finding.line_start != null && finding.line_start > 0;
  const codeSource = (fullSource && hasLineInfo) ? fullSource : (finding.code_snippet || fullSource || "");
  const origHLStart = hasLineInfo ? finding.line_start : 1;
  const origHLEnd = hasLineInfo
    ? (finding.line_end ?? finding.line_start)
    : (finding.code_snippet ? finding.code_snippet.split("\n").length : null);

  let fixCode = finding.fixed_code || "";
  let fixHLStart: number | null = null;
  let fixHLEnd: number | null = null;

  // Changed lines for full-file fixes (no line_start): compare line-by-line
  let fixChangedLines: Set<number> | null = null;

  if (finding.has_fix && finding.fixed_code && fullSource && finding.line_start && finding.line_end) {
    // Line-based fix: merge into full source
    const merged = getMergedCode(fullSource, finding.fixed_code, finding.line_start, finding.line_end);
    fixCode = merged.code;
    fixHLStart = merged.fixStart;
    fixHLEnd = merged.fixEnd;
  } else if (finding.has_fix && finding.fixed_code && fullSource && !finding.line_start) {
    // Full-file fix (dependency/config): diff to find changed lines
    fixCode = finding.fixed_code;
    const origLines = fullSource.split("\n");
    const fixLines = finding.fixed_code.split("\n");
    const changed = new Set<number>();
    const maxLen = Math.max(origLines.length, fixLines.length);
    for (let i = 0; i < maxLen; i++) {
      if (origLines[i] !== fixLines[i]) changed.add(i + 1);
    }
    fixChangedLines = changed;
    // For the range-based highlight, find first and last changed line
    if (changed.size > 0) {
      fixHLStart = Math.min(...changed);
      fixHLEnd = Math.max(...changed);
    }
  } else if (finding.has_fix && finding.fixed_code) {
    fixCode = finding.fixed_code;
    fixHLStart = 1;
    fixHLEnd = finding.fixed_code.split("\n").length;
  }

  return (
    <div className="space-y-6">
      <Toaster position="top-center" toastOptions={{ style: { background: "#0f1724", color: "#fff", border: "1px solid rgba(255,255,255,0.1)" } }} />

      {/* ===== Breadcrumb ===== */}
      <nav className="flex items-center gap-2 text-sm text-(--text-muted)">
        <Link href="/scans" className="hover:text-(--text) transition-colors">{t("app.findingDetail.scans")}</Link>
        <span className="material-symbols-outlined text-xs" aria-hidden>chevron_right</span>
        <Link href={`/scans/${scanId}`} className="hover:text-(--text) transition-colors">
          {t("app.findingDetail.project")}: {pName}
        </Link>
        <span className="material-symbols-outlined text-xs" aria-hidden>chevron_right</span>
        <span className="text-(--text)">{t("app.findingDetail.remediation")} #{finding.id.slice(0, 4).toUpperCase()}</span>
      </nav>

      {/* ===== Header ===== */}
      <div className="flex items-start justify-between gap-8">
        <div className="min-w-0 flex-1">
          {/* Tags */}
          <div className="flex items-center gap-2 flex-wrap mb-3 mt-3">
            <span className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-bold uppercase ${sev.bg} ${sev.color}`}>
              {sev.label}
            </span>
            {finding.owasp_category !== "UNK" && (
              <span className="inline-flex items-center rounded-full bg-blue-900/50 px-3 py-1 text-xs font-semibold text-blue-300">
                OWASP {finding.owasp_category}:2021-{OWASP_LABELS[finding.owasp_category] ?? "Unknown"}
              </span>
            )}
          </div>
          <h1 className="text-2xl font-bold text-(--text)">
            {finding.title} {t("app.findingDetail.remediation")}
          </h1>
          <p className="mt-2 mb-6 text-sm text-(--text-muted) leading-relaxed">
            {t("app.findingDetail.detectedBy")}{" "}
            <strong className="text-(--text)">{TOOL_LABELS[finding.tool] ?? finding.tool}</strong>
            {" "}{t("app.findingDetail.in")}{" "}
            <code className="rounded bg-slate-800 px-1.5 py-0.5 text-xs font-mono text-(--accent)">
              {finding.file_path}{finding.line_start ? `:${finding.line_start}` : ""}
            </code>
            {finding.has_fix && finding.fix_explanation && (
              <>. {t("app.findingDetail.aiSuggests")} <em className="text-(--text)">{finding.fix_explanation.split(".")[0]}.</em></>
            )}
          </p>
        </div>

        {/* Action buttons — stacked vertically on the right */}
        <div className="flex flex-col gap-2 shrink-0">
          {/* Status selector */}
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-(--text-muted)">Status:</span>
            <select
              value={finding.status}
              onChange={(e) => updateStatus(e.target.value)}
              className={`rounded-lg border border-(--border) px-3 py-1.5 text-xs font-medium outline-none ${
                FINDING_STATUS_OPTIONS.find((o) => o.value === finding.status)?.color ?? "bg-(--bg-card) text-(--text)"
              }`}
            >
              {FINDING_STATUS_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>

          <div className="flex gap-2">
            <button
              type="button"
              onClick={downloadPdf}
              className="inline-flex items-center gap-2 rounded-lg border border-(--border) bg-(--bg-card) px-4 py-2 text-sm font-medium text-(--text) hover:bg-white/5 transition-colors"
            >
              <span className="material-symbols-outlined text-base" aria-hidden>download</span>
              PDF
            </button>
            <button
              type="button"
              onClick={downloadHtml}
              className="inline-flex items-center gap-2 rounded-lg border border-(--border) bg-(--bg-card) px-4 py-2 text-sm font-medium text-(--text) hover:bg-white/5 transition-colors"
            >
              <span className="material-symbols-outlined text-base" aria-hidden>code</span>
              HTML
            </button>
          </div>

          {/* PR button — only for Git repos */}
          {scanMeta?.source_type === "git" && prUrl ? (
            <a
              href={prUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-lg bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 transition-colors"
            >
              <span className="material-symbols-outlined text-base" aria-hidden>open_in_new</span>
              {t("app.findingDetail.viewPr")}
            </a>
          ) : scanMeta?.source_type === "git" && finding.has_fix && !prUrl ? (
            <button
              type="button"
              onClick={handleApplyFix}
              disabled={applyingFix}
              className="inline-flex items-center gap-2 rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white hover:bg-(--accent-hover) transition-colors disabled:opacity-50"
            >
              {applyingFix ? (
                <><span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />{t("app.findingDetail.creatingPr")}</>
              ) : (
                <><span className="material-symbols-outlined text-base" aria-hidden>merge_type</span>{t("app.findingDetail.applyFix")}</>
              )}
            </button>
          ) : null}
          {/* Generate fix button */}
          {!finding.has_fix && (
            <button
              type="button"
              onClick={requestFix}
              disabled={fixLoading}
              className="inline-flex items-center gap-2 rounded-lg bg-purple-600 px-4 py-2 text-sm font-medium text-white hover:bg-purple-700 transition-colors disabled:opacity-50"
            >
              {fixLoading ? (
                <><span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />{t("app.findingDetail.generating")}</>
              ) : (
                <><span className="material-symbols-outlined text-base" aria-hidden>auto_fix_high</span>{t("app.findingDetail.generateAiFix")}</>
              )}
            </button>
          )}
          {(applyError || fixError) && (
            <p className="text-xs text-(--critical)">{applyError || fixError}</p>
          )}
        </div>
      </div>

      {/* ===== Main grid: 1/3 left + 2/3 right ===== */}
      <div className="grid gap-6 lg:grid-cols-3">

        {/* ---------- LEFT COLUMN ---------- */}
        <div className="space-y-5">

          {/* Fix Analysis */}
          <section className="rounded-xl border border-(--border) bg-(--bg-card) p-5">
            {finding.has_fix && finding.fix_explanation ? (
              <div className="space-y-3">
                <h2 className="flex items-center gap-2 text-sm font-semibold text-(--text) mb-2">
                  {isPatternFix ? (
                    <>
                      <span className="material-symbols-outlined text-lg text-emerald-400" aria-hidden>build</span>
                      {t("app.findingDetail.patternFix") || "Pattern-based Fix"}
                    </>
                  ) : (
                    <>
                      <span className="material-symbols-outlined text-lg text-purple-400" aria-hidden>auto_awesome</span>
                      {t("app.findingDetail.aiAnalysis")}
                    </>
                  )}
                </h2>
                {isPatternFix && (
                  <div className="flex items-center gap-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 px-3 py-2">
                    <span className="material-symbols-outlined text-sm text-emerald-400" aria-hidden>bolt</span>
                    <span className="text-xs font-medium text-emerald-300">
                      {t("app.findingDetail.patternFixLabel") || "Deterministic fix — no AI needed"}
                    </span>
                  </div>
                )}
                <div className={`flex items-start gap-3 rounded-lg p-3 ${
                  isPatternFix
                    ? "bg-emerald-500/10 border border-emerald-500/20"
                    : "bg-blue-500/10 border border-blue-500/20"
                }`}>
                  <span className={`material-symbols-outlined text-sm mt-0.5 shrink-0 ${
                    isPatternFix ? "text-emerald-400" : "text-blue-400"
                  }`} aria-hidden>verified</span>
                  <p className="text-sm text-(--text) leading-relaxed">{finding.fix_explanation}</p>
                </div>
              </div>
            ) : (
              <div>
                <h2 className="flex items-center gap-2 text-sm font-semibold text-(--text) mb-2">
                  <span className="material-symbols-outlined text-lg text-slate-400" aria-hidden>info</span>
                  {t("app.findingDetail.scannerDescription")}
                </h2>
                {fixLoading ? (
                  <div className="flex items-center gap-3">
                    <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-purple-400/30 border-t-purple-400" />
                    <span className="text-sm text-(--text)">{t("app.findingDetail.generatingAiAnalysis")}</span>
                  </div>
                ) : (
                  <p className="text-sm text-(--text-muted) leading-relaxed">
                    {finding.description || t("app.findingDetail.clickGenerate")}
                  </p>
                )}
              </div>
            )}
          </section>

          {/* Confidence + Effort */}
          <div className="grid grid-cols-2 gap-3 mt-6 mb-6">
            <div className="rounded-xl border border-(--border) bg-(--bg-card) p-4">
              <p className="text-[10px] font-bold uppercase tracking-widest text-(--text-muted)">{t("app.findingDetail.confidenceScore")}</p>
              <div className="mt-2 flex items-baseline gap-1">
                <span className="text-2xl font-bold text-(--success)">{finding.has_fix ? "98%" : "—"}</span>
                {finding.has_fix && <span className="text-xs font-medium text-(--success)">{t("app.findingDetail.high")}</span>}
              </div>
              {finding.has_fix && (
                <div className="mt-2 h-1 w-full rounded-full bg-white/10">
                  <div className="h-full rounded-full bg-(--success)" style={{ width: "98%" }} />
                </div>
              )}
            </div>
            <div className="rounded-xl border border-(--border) bg-(--bg-card) p-4">
              <p className="text-[10px] font-bold uppercase tracking-widest text-(--text-muted)">{t("app.findingDetail.estimatedEffort")}</p>
              <div className="mt-2 flex items-baseline gap-1">
                <span className="text-2xl font-bold text-(--accent)">{finding.has_fix ? "5m" : "—"}</span>
                {finding.has_fix && <span className="text-xs font-medium text-(--text-muted)">{t("app.findingDetail.toFix")}</span>}
              </div>
              {finding.has_fix && (
                <div className="mt-2 h-1 w-full rounded-full bg-white/10">
                  <div className="h-full rounded-full bg-(--accent)" style={{ width: "15%" }} />
                </div>
              )}
            </div>
          </div>

          {/* References */}
          <section className="rounded-xl border border-(--border) bg-(--bg-card) p-5">
            <h2 className="text-sm font-semibold text-(--text) mb-3">{t("app.findingDetail.references")}</h2>
            <ul className="space-y-0.5">
              {finding.owasp_category !== "UNK" && (
                <li>
                  <a
                    href={OWASP_LINKS[finding.owasp_category] ?? "https://owasp.org/Top10/"}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-between gap-3 rounded-lg px-2 py-2 text-sm text-(--text-muted) hover:bg-white/5 hover:text-(--text) transition-colors"
                  >
                    <span className="leading-snug">OWASP {finding.owasp_category} — {OWASP_LABELS[finding.owasp_category]}</span>
                    <span className="material-symbols-outlined shrink-0 text-sm" aria-hidden>open_in_new</span>
                  </a>
                </li>
              )}
              <li>
                <a
                  href="https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-between gap-3 rounded-lg px-2 py-2 text-sm text-(--text-muted) hover:bg-white/5 hover:text-(--text) transition-colors"
                >
                  <span className="leading-snug">OWASP Injection Prevention Cheat Sheet</span>
                  <span className="material-symbols-outlined shrink-0 text-sm" aria-hidden>open_in_new</span>
                </a>
              </li>
            </ul>
            {finding.rule_id && (
              <div className="mt-3 border-t border-(--border) pt-3">
                <p className="text-xs font-semibold uppercase tracking-wider text-(--text-muted) mb-1.5">
                  {TOOL_LABELS[finding.tool] ?? finding.tool} {t("app.findingDetail.rule")}
                </p>
                <p className="font-mono text-xs text-(--text) break-all leading-relaxed">{finding.rule_id}</p>
              </div>
            )}
          </section>
        </div>

        {/* ---------- RIGHT COLUMN (2/3) — Code diff panel ---------- */}
        <div className="lg:col-span-2">
          <section className="rounded-xl border border-(--border) bg-[#0d1117] overflow-hidden flex flex-col">

            {/* Panel header bar */}
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-700/50 bg-[#161b22]">
              <div className="flex items-center gap-3 text-xs">
                <span className="flex items-center gap-1.5 text-red-300 font-medium">
                  <span className="h-2 w-2 rounded-full bg-red-500" />
                  {t("app.findingDetail.originalInsecure")}
                </span>
                {finding.has_fix && (
                  <>
                    <span className="text-slate-600">|</span>
                    <span className="flex items-center gap-1.5 text-green-300 font-medium">
                      <span className="h-2 w-2 rounded-full bg-green-500" />
                      {t("app.findingDetail.suggestedFix")}
                    </span>
                  </>
                )}
              </div>
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => navigator.clipboard.writeText(codeSource)}
                  className="p-1.5 rounded hover:bg-white/10 transition-colors text-slate-400 hover:text-slate-200"
                  title={t("app.findingDetail.copyCode")}
                >
                  <span className="material-symbols-outlined text-sm" aria-hidden>content_copy</span>
                </button>
              </div>
            </div>

            {/* Code body — side-by-side when fix available, full-width otherwise */}
            {finding.has_fix && fixCode ? (
              <div className="grid grid-cols-2 divide-x divide-slate-700/50">
                <div className="min-w-0">
                  <CodeViewer
                    code={codeSource}
                    highlightStart={origHLStart}
                    highlightEnd={origHLEnd}
                    highlightColor="red"
                    language={prismLang}
                  />
                </div>
                <div className="min-w-0">
                  <CodeViewer
                    code={fixCode}
                    highlightStart={fixHLStart}
                    highlightEnd={fixHLEnd}
                    highlightColor="green"
                    language={prismLang}
                    highlightLines={fixChangedLines}
                  />
                </div>
              </div>
            ) : (
              <CodeViewer
                code={codeSource}
                highlightStart={origHLStart}
                highlightEnd={origHLEnd}
                highlightColor="red"
                language={prismLang}
              />
            )}
          </section>
        </div>
      </div>

      {/* ===== Other Occurrences ===== */}
      {otherOccurrences.length > 0 && (
        <section>
          <h2 className="text-xs font-bold uppercase tracking-widest text-(--text-muted) mt-4 mb-3">
            {t("app.findingDetail.otherOccurrences")}
          </h2>
          <div className="grid gap-3 sm:grid-cols-2">
            {otherOccurrences.map((occ) => {
              const occSev = SEVERITY_CONFIG[occ.severity] ?? SEVERITY_CONFIG.info;
              return (
                <Link
                  key={occ.id}
                  href={`/scans/${scanId}/findings/${occ.id}`}
                  className="flex items-center gap-3 rounded-xl border border-(--border) bg-(--bg-card) px-4 py-3.5 hover:bg-white/5 transition-colors"
                >
                  <span className={`material-symbols-outlined text-lg ${occSev.color}`} aria-hidden>
                    {occ.severity === "critical" || occ.severity === "high" ? "warning" : "info"}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-(--text) truncate">
                      {t("app.findingDetail.line")} {occ.line_start ?? "?"}: {occ.title}
                    </p>
                    <p className="text-xs text-(--text-muted) truncate mt-0.5">
                      {occ.description?.slice(0, 80) || occ.rule_id}
                    </p>
                  </div>
                  <span className="material-symbols-outlined text-(--text-muted) text-lg" aria-hidden>chevron_right</span>
                </Link>
              );
            })}
          </div>
        </section>
      )}
    </div>
  );
}
