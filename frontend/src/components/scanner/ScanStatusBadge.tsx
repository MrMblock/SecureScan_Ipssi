"use client";

/**
 * ScanStatusBadge — color-coded pill badge for scan status.
 *
 * Uses the project's CSS custom property color system (--accent, --success,
 * --critical, --text-muted, etc.) via Tailwind bg and text utility classes.
 */

import { useTranslation } from "@/i18n";

interface ScanStatusBadgeProps {
  status: string;
}

const STATUS_STYLE_CONFIG: Record<
  string,
  { bgClass: string; textClass: string }
> = {
  pending: {
    bgClass: "bg-slate-700",
    textClass: "text-slate-300",
  },
  cloning: {
    bgClass: "bg-blue-900",
    textClass: "text-blue-300",
  },
  detecting: {
    bgClass: "bg-yellow-900",
    textClass: "text-yellow-300",
  },
  scanning: {
    bgClass: "bg-blue-900",
    textClass: "text-blue-300",
  },
  aggregating: {
    bgClass: "bg-blue-900",
    textClass: "text-blue-300",
  },
  completed: {
    bgClass: "bg-green-900",
    textClass: "text-green-300",
  },
  failed: {
    bgClass: "bg-red-900",
    textClass: "text-red-300",
  },
};

export default function ScanStatusBadge({ status }: ScanStatusBadgeProps) {
  const { t } = useTranslation();

  const STATUS_LABELS: Record<string, string> = {
    pending: t("scanner.status.pending"),
    cloning: t("scanner.status.cloning"),
    detecting: t("scanner.status.detecting"),
    scanning: t("scanner.status.scanning"),
    aggregating: t("scanner.status.aggregating"),
    completed: t("scanner.status.completed"),
    failed: t("scanner.status.failed"),
  };

  const styleConfig = STATUS_STYLE_CONFIG[status] ?? {
    bgClass: "bg-slate-700",
    textClass: "text-slate-300",
  };

  const label = STATUS_LABELS[status] ?? status;

  return (
    <span
      className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wide ${styleConfig.bgClass} ${styleConfig.textClass}`}
    >
      {label}
    </span>
  );
}
