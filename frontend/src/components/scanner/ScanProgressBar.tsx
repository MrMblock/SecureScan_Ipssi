"use client";

const STEPS = [
  { key: "pending", label: "Queued", icon: "schedule" },
  { key: "cloning", label: "Cloning", icon: "download" },
  { key: "crawling", label: "Crawling", icon: "travel_explore" },
  { key: "detecting", label: "Detecting", icon: "search" },
  { key: "scanning", label: "Scanning", icon: "radar" },
  { key: "aggregating", label: "Aggregating", icon: "analytics" },
  { key: "completed", label: "Done", icon: "check_circle" },
];

interface ScanProgressBarProps {
  status: string;
}

export default function ScanProgressBar({ status }: ScanProgressBarProps) {
  const isFailed = status === "failed";
  const currentIdx = STEPS.findIndex((s) => s.key === status);
  const activeIdx = isFailed ? -1 : currentIdx;

  // Progress percentage for the bar fill
  const progress =
    isFailed
      ? 0
      : status === "completed"
      ? 100
      : currentIdx >= 0
      ? (currentIdx / (STEPS.length - 1)) * 100
      : 0;

  return (
    <div className="space-y-6">
      {/* Bar */}
      <div className="relative h-2.5 w-full overflow-hidden rounded-full bg-white/10">
        <div
          className={`absolute inset-y-0 left-0 rounded-full transition-all duration-700 ease-out ${
            isFailed
              ? "bg-red-500"
              : status === "completed"
              ? "bg-emerald-500"
              : "bg-(--accent)"
          }`}
          style={{ width: `${progress}%` }}
        />
        {/* Pulse on active bar */}
        {!isFailed && status !== "completed" && (
          <div
            className="absolute inset-y-0 left-0 animate-pulse rounded-full bg-white/20"
            style={{ width: `${progress}%` }}
          />
        )}
      </div>

      {/* Steps */}
      <div className="mt-4 flex justify-between">
        {STEPS.map((step, i) => {
          const isDone = activeIdx > i;
          const isActive = activeIdx === i;
          const isPending = activeIdx < i;

          return (
            <div
              key={step.key}
              className={`flex flex-col items-center gap-2.5 text-center ${
                isDone
                  ? "text-emerald-400"
                  : isActive
                  ? "text-white"
                  : isFailed && i === 0
                  ? "text-red-400"
                  : isPending
                  ? "text-white/30"
                  : "text-white/60"
              }`}
            >
              <span
                className={`material-symbols-outlined text-xl ${
                  isActive && !isFailed ? "animate-pulse" : ""
                }`}
              >
                {isFailed && isActive
                  ? "error"
                  : isDone
                  ? "check_circle"
                  : step.icon}
              </span>
              <span className="text-xs font-semibold text-white">
                {step.label}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
