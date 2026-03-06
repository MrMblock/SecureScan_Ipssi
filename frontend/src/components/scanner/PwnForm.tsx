"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { AnimatePresence, motion } from "motion/react";
import { useTranslation } from "@/i18n";
import { usePwnProgress, type PwnProgress } from "@/hooks/usePwnProgress";

const PHASES = ["recon", "nmap", "ssl", "nuclei", "dast", "aggregate"] as const;

const PHASE_ICONS: Record<string, { icon: string; label: string }> = {
  recon: { icon: "travel_explore", label: "Recon" },
  nmap: { icon: "lan", label: "Nmap" },
  ssl: { icon: "lock", label: "SSL/TLS" },
  nuclei: { icon: "bug_report", label: "Nuclei" },
  dast: { icon: "web", label: "DAST" },
  aggregate: { icon: "assessment", label: "Results" },
};

export default function PwnForm() {
  const { t } = useTranslation();
  const router = useRouter();
  const { state, startPwn, reset } = usePwnProgress();
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  const [focused, setFocused] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    const trimmed = url.trim();
    if (!trimmed) {
      setError(t("app.pwn.errorUrl"));
      return;
    }

    try {
      new URL(trimmed);
    } catch {
      setError(t("app.pwn.errorUrl"));
      return;
    }

    try {
      await startPwn(trimmed);
    } catch (err: unknown) {
      if (err && typeof err === "object" && "response" in err) {
        const res = (err as { response?: { status?: number } }).response;
        if (res?.status === 401) {
          setError("You must be logged in to launch a pentest.");
          return;
        }
      }
      setError(t("app.pwn.errorUrl"));
    }
  };

  return (
    <section className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-gradient-to-br from-[#0d1117] via-[#111827] to-[#0d1117]">
      {/* Animated background grid */}
      <div className="pointer-events-none absolute inset-0 opacity-[0.03]" style={{
        backgroundImage: `linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)`,
        backgroundSize: "40px 40px",
      }} />

      {/* Glow effects */}
      <div className="pointer-events-none absolute -top-32 left-1/2 -translate-x-1/2 h-64 w-96 rounded-full bg-(--accent)/[0.08] blur-[100px]" />
      <div className="pointer-events-none absolute -bottom-20 -right-20 h-40 w-40 rounded-full bg-purple-500/[0.06] blur-[80px]" />

      <div className="relative p-8">
        {/* Header */}
        <div className="mb-6 flex items-start gap-4">
          <div className="relative">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-(--accent)/30 to-(--accent)/10 border border-(--accent)/20">
              <span className="material-symbols-outlined text-2xl text-(--accent-light)">terminal</span>
            </div>
            {state.status === "running" && (
              <motion.div
                className="absolute -top-0.5 -right-0.5 h-3 w-3 rounded-full bg-(--accent)"
                animate={{ scale: [1, 1.3, 1], opacity: [1, 0.5, 1] }}
                transition={{ duration: 1.5, repeat: Infinity }}
              />
            )}
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-white">{t("app.pwn.title")}</h2>
              <span className="rounded-md bg-(--accent)/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-(--accent-light)">
                DAST
              </span>
            </div>
            <p className="mt-1 text-sm text-white/40">{t("app.pwn.subtitle")}</p>
          </div>
        </div>

        <AnimatePresence mode="wait">
          {/* IDLE */}
          {state.status === "idle" && (
            <motion.form
              key="idle"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.3 }}
              onSubmit={handleSubmit}
              className="space-y-4"
            >
              {/* Terminal-style input */}
              <div className={`relative rounded-xl border transition-all duration-300 ${
                focused
                  ? "border-(--accent)/40 bg-white/[0.03] shadow-[0_0_30px_-5px] shadow-(--accent)/10"
                  : "border-white/[0.08] bg-white/[0.02]"
              }`}>
                <div className="flex items-center gap-3 px-4 py-1 border-b border-white/[0.06]">
                  <div className="flex gap-1.5">
                    <div className="h-2.5 w-2.5 rounded-full bg-red-500/60" />
                    <div className="h-2.5 w-2.5 rounded-full bg-yellow-500/60" />
                    <div className="h-2.5 w-2.5 rounded-full bg-green-500/60" />
                  </div>
                  <span className="text-[11px] text-white/20 font-mono">securescan ~ pentest</span>
                </div>
                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 sm:gap-3 p-4">
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <span className="text-sm font-mono text-(--accent)/70 select-none">$</span>
                    <input
                      type="text"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      onFocus={() => setFocused(true)}
                      onBlur={() => setFocused(false)}
                      placeholder="https://target.com"
                      className="flex-1 min-w-0 bg-transparent text-sm font-mono text-white placeholder:text-white/20 outline-none"
                    />
                  </div>
                  <button
                    type="submit"
                    className="group flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-(--accent) to-(--accent-hover) px-5 py-2 text-sm font-semibold text-white transition-all hover:shadow-lg hover:shadow-(--accent)/20 active:scale-[0.97] shrink-0"
                  >
                    <span className="material-symbols-outlined text-base transition-transform group-hover:translate-x-0.5">rocket_launch</span>
                    {t("app.pwn.launch")}
                  </button>
                </div>
              </div>

              {error && (
                <motion.p
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="flex items-center gap-1.5 text-xs text-red-400"
                >
                  <span className="material-symbols-outlined text-sm">error</span>
                  {error}
                </motion.p>
              )}

              {/* Info bar */}
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 rounded-lg bg-white/[0.02] px-4 py-2.5 border border-white/[0.04]">
                <p className="text-[11px] text-white/30">{t("app.pwn.disclaimer")}</p>
                <div className="flex items-center gap-3">
                  {["Nmap", "Nuclei", "SSLyze", "DAST"].map((tool) => (
                    <span key={tool} className="text-[10px] font-mono text-white/20">{tool}</span>
                  ))}
                </div>
              </div>
            </motion.form>
          )}

          {/* RUNNING */}
          {state.status === "running" && (
            <motion.div
              key="running"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              transition={{ duration: 0.3 }}
              className="space-y-6"
            >
              <ProgressDisplay progress={state.progress} />
              <PhaseTimeline currentPhase={state.progress.phase} />

              {/* Status bar */}
              <div className="mt-4 flex items-center justify-between rounded-lg bg-white/[0.03] px-4 py-3 border border-white/[0.06]">
                <div className="flex items-center gap-2">
                  <motion.div
                    className="h-2 w-2 rounded-full bg-(--accent)"
                    animate={{ opacity: [1, 0.3, 1] }}
                    transition={{ duration: 1, repeat: Infinity }}
                  />
                  <p className="text-xs text-white/60 font-mono">
                    {state.progress.message}
                  </p>
                </div>
                <div className="flex items-center gap-4">
                  {state.progress.findings_so_far > 0 && (
                    <span className="text-xs font-semibold text-white">
                      {state.progress.findings_so_far} findings
                    </span>
                  )}
                  <button
                    onClick={reset}
                    className="text-[11px] text-white/40 hover:text-white/70 transition-colors font-mono"
                  >
                    [cancel]
                  </button>
                </div>
              </div>

              <p className="mt-2 text-xs text-white/40 text-center">
                {t("app.pwn.canNavigate")}
              </p>
            </motion.div>
          )}

          {/* COMPLETED */}
          {state.status === "completed" && (
            <motion.div
              key="completed"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.4, type: "spring" }}
              className="space-y-5"
            >
              <div className="relative overflow-hidden rounded-xl bg-gradient-to-r from-(--success)/10 to-transparent border border-(--success)/20 p-5">
                <div className="pointer-events-none absolute -right-8 -top-8 h-24 w-24 rounded-full bg-(--success)/10 blur-2xl" />
                <div className="relative flex items-center gap-4">
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-(--success)/20">
                    <span className="material-symbols-outlined text-2xl text-(--success)">
                      verified
                    </span>
                  </div>
                  <div>
                    <p className="text-lg font-bold text-(--success)">
                      {t("app.pwn.complete")}
                    </p>
                    <p className="text-sm text-white/50">
                      <span className="font-semibold text-white/70">{state.totalFindings}</span> vulnerabilities detected
                    </p>
                  </div>
                </div>
              </div>

              <div className="mt-4 flex gap-3">
                <button
                  onClick={() => router.push(`/scans/${state.scanId}`)}
                  className="flex-1 flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-(--accent) to-(--accent-hover) py-3 text-sm font-semibold text-white transition-all hover:shadow-lg hover:shadow-(--accent)/20"
                >
                  <span className="material-symbols-outlined text-base">visibility</span>
                  {t("app.pwn.viewResults")}
                </button>
                <button
                  onClick={reset}
                  className="rounded-xl border border-white/10 px-5 py-3 text-sm font-medium text-white/60 transition-all hover:bg-white/5 hover:text-white/80"
                >
                  New
                </button>
              </div>
            </motion.div>
          )}

          {/* FAILED */}
          {state.status === "failed" && (
            <motion.div
              key="failed"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3 }}
              className="space-y-4"
            >
              <div className="relative overflow-hidden rounded-xl bg-gradient-to-r from-red-500/10 to-transparent border border-red-500/20 p-5">
                <div className="relative flex items-center gap-4">
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-500/20">
                    <span className="material-symbols-outlined text-2xl text-red-400">
                      error
                    </span>
                  </div>
                  <div>
                    <p className="text-lg font-bold text-red-400">Scan Failed</p>
                    <p className="text-sm text-white/50">{state.error}</p>
                  </div>
                </div>
              </div>
              <button
                onClick={reset}
                className="w-full rounded-xl border border-white/10 py-3 text-sm font-medium text-white/60 transition-all hover:bg-white/5 hover:text-white/80"
              >
                Try Again
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </section>
  );
}

/* ---- Sub-components ---- */

function formatEta(seconds: number | null): string | null {
  if (seconds === null || seconds <= 0) return null;
  if (seconds < 60) return `~${seconds}s`;
  const min = Math.floor(seconds / 60);
  const sec = seconds % 60;
  return sec > 0 ? `~${min}m ${sec}s` : `~${min}m`;
}

function ProgressDisplay({ progress }: { progress: PwnProgress }) {
  const eta = formatEta(progress.etaSeconds);

  return (
    <div className="space-y-5">
      <div className="flex items-end justify-between">
        <div className="flex items-baseline gap-2">
          <span className="text-4xl font-black tracking-tight text-white">
            {progress.percent}
          </span>
          <span className="text-lg font-bold text-white/40">%</span>
        </div>
        <div className="text-right">
          <span className="text-sm font-semibold text-white">
            {progress.phase_label}
          </span>
          {eta && (
            <p className="mt-1 text-xs text-white/40 font-mono">{eta} remaining</p>
          )}
        </div>
      </div>

      {/* Progress bar */}
      <div className="relative h-2 w-full overflow-hidden rounded-full bg-white/[0.08]">
        <motion.div
          className="absolute inset-y-0 left-0 rounded-full bg-gradient-to-r from-(--accent) via-(--accent-light) to-(--accent)"
          initial={{ width: "0%" }}
          animate={{ width: `${progress.percent}%` }}
          transition={{ duration: 0.6, ease: "easeOut" }}
        />
        <motion.div
          className="absolute inset-y-0 left-0 rounded-full bg-white/30"
          style={{ width: `${progress.percent}%` }}
          animate={{ opacity: [0.4, 0, 0.4] }}
          transition={{ duration: 1.2, repeat: Infinity }}
        />
      </div>
    </div>
  );
}

function PhaseTimeline({ currentPhase }: { currentPhase: string }) {
  const phaseIndex = PHASES.indexOf(currentPhase as (typeof PHASES)[number]);

  return (
    <div className="mt-8 flex items-center gap-0.5 sm:gap-1">
      {PHASES.map((phase, i) => {
        const info = PHASE_ICONS[phase];
        const isPast = i < phaseIndex;
        const isActive = phase === currentPhase;

        return (
          <div key={phase} className="flex flex-1 flex-col items-center gap-3">
            {/* Connector line + icon */}
            <div className="flex w-full items-center">
              {/* Left connector — invisible spacer for first item to keep icon centered */}
              <div className={`h-px flex-1 transition-colors duration-500 ${
                i === 0 ? "bg-transparent" : isPast ? "bg-(--accent)/50" : "bg-white/[0.08]"
              }`} />
              <div className="relative shrink-0">
                <div
                  className={`flex h-8 w-8 sm:h-10 sm:w-10 items-center justify-center rounded-xl transition-all duration-300 ${
                    isPast
                      ? "bg-(--success)/15 border border-(--success)/30"
                      : isActive
                        ? "bg-(--accent)/15 border border-(--accent)/30"
                        : "bg-white/[0.04] border border-white/[0.08]"
                  }`}
                >
                  {isPast ? (
                    <span className="material-symbols-outlined text-base text-(--success)">check</span>
                  ) : (
                    <span
                      className={`material-symbols-outlined text-base ${
                        isActive ? "text-white" : "text-white/30"
                      }`}
                    >
                      {info.icon}
                    </span>
                  )}
                </div>
                {isActive && (
                  <motion.div
                    className="absolute inset-0 rounded-xl border border-(--accent)/50"
                    animate={{ scale: [1, 1.2, 1], opacity: [0.5, 0, 0.5] }}
                    transition={{ duration: 2, repeat: Infinity }}
                  />
                )}
              </div>
              {/* Right connector — invisible spacer for last item to keep icon centered */}
              <div className={`h-px flex-1 transition-colors duration-500 ${
                i === PHASES.length - 1 ? "bg-transparent" : isPast ? "bg-(--accent)/50" : "bg-white/[0.08]"
              }`} />
            </div>
            <span
              className={`text-[10px] sm:text-xs font-semibold transition-colors ${
                isPast
                  ? "text-emerald-400"
                  : isActive
                    ? "text-white"
                    : "text-white/30"
              }`}
            >
              {info.label}
            </span>
          </div>
        );
      })}
    </div>
  );
}
