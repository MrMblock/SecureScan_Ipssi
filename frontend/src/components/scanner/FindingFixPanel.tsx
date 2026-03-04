"use client";

import { useEffect, useState } from "react";
import axios from "axios";
import toast from "react-hot-toast";
import api from "@/lib/api";
import { useTranslation } from "@/i18n";

interface FixResult {
  fixed_code: string;
  fix_explanation: string;
  original_code: string;
  file_path: string;
  line_start: number | null;
  cached: boolean;
}

interface FindingFixPanelProps {
  findingId: string;
  originalCode: string;
  /** If a fix was already cached, pass it to avoid an extra request. */
  initialFix?: FixResult | null;
  /** If a PR was already created, show the link. */
  existingPrUrl?: string;
  /** Whether the scan source is a Git repo (enables PR creation). */
  isGitRepo?: boolean;
}

export default function FindingFixPanel({
  findingId,
  originalCode,
  initialFix = null,
  existingPrUrl = "",
  isGitRepo = false,
}: FindingFixPanelProps) {
  const { t, locale } = useTranslation();
  const [fix, setFix] = useState<FixResult | null>(initialFix);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"original" | "fix">("original");
  const [hasAiKey, setHasAiKey] = useState<boolean | null>(null);

  useEffect(() => {
    api.get("/api/accounts/me/").then((res) => {
      const d = res.data;
      const provider = d.ai_provider || "gemini";
      const keyMap: Record<string, string> = { gemini: d.gemini_api_key, openai: d.openai_api_key, anthropic: d.anthropic_api_key };
      setHasAiKey(!!keyMap[provider]);
    }).catch(() => {});
  }, []);

  // PR state
  const [prUrl, setPrUrl] = useState<string>(existingPrUrl);
  const [applyingFix, setApplyingFix] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);

  const requestFix = async (force = false) => {
    if (!hasAiKey) {
      toast.error(t("app.settings.aiKeyRequired"));
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await api.post(`/api/scanner/findings/${findingId}/fix/`, { lang: locale, force });
      setFix(res.data);
      setActiveTab("fix");
    } catch (err: unknown) {
      const msg =
        axios.isAxiosError(err) && err.response?.data?.detail
          ? err.response.data.detail
          : "Failed to generate fix. Please try again.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const [manualOnly, setManualOnly] = useState(false);

  const copyFixToClipboard = () => {
    if (fix?.fixed_code) {
      navigator.clipboard.writeText(fix.fixed_code);
      toast.success(t("common.copiedToClipboard"));
    }
  };

  const applyFixAndCreatePr = async () => {
    setApplyingFix(true);
    setApplyError(null);
    setManualOnly(false);
    try {
      const res = await api.post(`/api/scanner/findings/${findingId}/apply/`);
      setPrUrl(res.data.pr_url);
    } catch (err: unknown) {
      const detail =
        axios.isAxiosError(err) && err.response?.data?.detail
          ? err.response.data.detail
          : "";
      if (detail === "manual_fix_required") {
        setManualOnly(true);
      } else {
        setApplyError(detail || "Failed to create PR. Check your GitHub token.");
      }
    } finally {
      setApplyingFix(false);
    }
  };

  // No fix requested yet — show button
  if (!fix && !loading) {
    return (
      <div className="mt-3 flex flex-col items-start gap-2">
        <button
          type="button"
          onClick={requestFix}
          className="inline-flex items-center gap-2 rounded-lg bg-purple-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-purple-700 transition-colors"
        >
          <span className="material-symbols-outlined text-lg" aria-hidden>
            auto_fix_high
          </span>
          {t("common.fixWithAi")}
        </button>
        {error && <p className="text-sm text-(--critical)">{error}</p>}
      </div>
    );
  }

  // Loading state
  if (loading) {
    return (
      <div className="mt-3 rounded-lg border border-purple-500/30 bg-purple-500/10 p-4">
        <div className="flex items-center gap-3">
          <span className="inline-block h-5 w-5 animate-spin rounded-full border-2 border-purple-400/30 border-t-purple-400" />
          <span className="text-sm text-(--text)">{t("common.generatingFix")}</span>
        </div>
      </div>
    );
  }

  // Fix available — show tabs + Apply button
  return (
    <div className="mt-3 rounded-lg border border-(--border) bg-(--bg-main) overflow-hidden">
      {/* AI explanation banner */}
      {fix!.fix_explanation && (
        <div className="border-b border-(--border) bg-purple-500/10 px-4 py-3">
          <div className="flex items-start gap-2">
            <span className="material-symbols-outlined text-purple-400 text-lg mt-0.5" aria-hidden>
              psychology
            </span>
            <div>
              <p className="text-xs font-semibold text-purple-400 uppercase tracking-wide">
                {t("common.aiAnalysis")}
              </p>
              <p className="mt-1 text-sm text-(--text)">{fix!.fix_explanation}</p>
            </div>
          </div>
        </div>
      )}

      {/* Tab switcher */}
      <div className="flex border-b border-(--border)">
        <button
          type="button"
          onClick={() => setActiveTab("original")}
          className={`flex-1 px-4 py-2.5 text-sm font-medium transition-colors flex items-center justify-center gap-1.5 ${
            activeTab === "original"
              ? "bg-red-500/15 text-red-400 border-b-2 border-red-400"
              : "text-(--text-muted) hover:text-(--text)"
          }`}
        >
          <span className="inline-block w-2 h-2 rounded-full bg-red-500" />
          {t("common.original")}
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("fix")}
          className={`flex-1 px-4 py-2.5 text-sm font-medium transition-colors flex items-center justify-center gap-1.5 ${
            activeTab === "fix"
              ? "bg-green-500/15 text-green-400 border-b-2 border-green-400"
              : "text-(--text-muted) hover:text-(--text)"
          }`}
        >
          <span className="inline-block w-2 h-2 rounded-full bg-green-500" />
          {t("common.suggestedFix")}
        </button>
      </div>

      {/* Code display */}
      <pre
        className={`p-4 text-xs overflow-auto max-h-64 ${
          activeTab === "original"
            ? "bg-red-500/10 text-red-400"
            : "bg-green-500/10 text-green-400"
        }`}
      >
        {activeTab === "original" ? originalCode : fix!.fixed_code}
      </pre>

      {/* Footer: Apply PR / Manual fix / Copy */}
      <div className="border-t border-(--border) px-4 py-3 flex items-center gap-3 flex-wrap">
        {prUrl ? (
          <a
            href={prUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-lg bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 transition-colors"
          >
            <span className="material-symbols-outlined text-lg" aria-hidden>
              open_in_new
            </span>
            {t("common.viewPrGithub")}
          </a>
        ) : manualOnly ? (
          <>
            <div className="flex items-center gap-2 rounded-lg bg-amber-500/10 border border-amber-500/30 px-4 py-2">
              <span className="material-symbols-outlined text-amber-400 text-lg" aria-hidden>info</span>
              <span className="text-sm text-amber-300">{t("common.manualFixRequired")}</span>
            </div>
            <button
              type="button"
              onClick={copyFixToClipboard}
              className="inline-flex items-center gap-2 rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-(--accent-hover) transition-colors"
            >
              <span className="material-symbols-outlined text-lg" aria-hidden>content_copy</span>
              {t("common.copyFix")}
            </button>
          </>
        ) : isGitRepo ? (
          <button
            type="button"
            onClick={applyFixAndCreatePr}
            disabled={applyingFix}
            className="inline-flex items-center gap-2 rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-(--accent-hover) transition-colors disabled:opacity-50"
          >
            {applyingFix ? (
              <>
                <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                {t("common.creatingPr")}
              </>
            ) : (
              <>
                <span className="material-symbols-outlined text-lg" aria-hidden>
                  merge_type
                </span>
                {t("common.applyFixCreatePr")}
              </>
            )}
          </button>
        ) : (
          <button
            type="button"
            onClick={copyFixToClipboard}
            className="inline-flex items-center gap-2 rounded-lg bg-(--accent) px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-(--accent-hover) transition-colors"
          >
            <span className="material-symbols-outlined text-lg" aria-hidden>content_copy</span>
            {t("common.copyFix")}
          </button>
        )}
        {!prUrl && (
          <button
            type="button"
            onClick={() => requestFix(true)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-(--border) px-3 py-2 text-xs font-medium text-(--text-muted) hover:text-(--text) hover:bg-white/5 transition-colors"
          >
            <span className="material-symbols-outlined text-sm" aria-hidden>refresh</span>
            {t("common.regenerate")}
          </button>
        )}
        {applyError && <p className="text-sm text-(--critical)">{applyError}</p>}
      </div>
    </div>
  );
}
