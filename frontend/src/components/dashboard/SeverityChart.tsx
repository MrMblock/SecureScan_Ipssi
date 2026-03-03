"use client";

import { useState, useEffect } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Cell,
} from "recharts";

/** Couleurs OWASP maquette : Critical, High, Medium, Low */
const OWASP_COLORS = {
  critical: "#ff4c4c",
  high: "#f39c12",
  medium: "#f1c40f",
  low: "#3498db",
};

/** Données simples : une barre par catégorie */
export type SimpleChartData = { name: string; count: number; fill?: string }[];

/** Données empilées par sévérité (maquette OWASP) */
export type StackedChartData = {
  name: string;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
}[];

const placeholderData: SimpleChartData = [
  { name: "A01 Access Control", count: 0, fill: OWASP_COLORS.critical },
  { name: "A02 Misconfiguration", count: 0, fill: OWASP_COLORS.high },
  { name: "A03 Supply Chain", count: 0, fill: OWASP_COLORS.medium },
  { name: "A04 Cryptographic", count: 0, fill: OWASP_COLORS.low },
  { name: "A05 Injection", count: 0, fill: OWASP_COLORS.critical },
  { name: "A06 Insecure Design", count: 0, fill: OWASP_COLORS.high },
  { name: "A07 Auth Failures", count: 0, fill: OWASP_COLORS.medium },
  { name: "A08 Integrity", count: 0, fill: OWASP_COLORS.low },
  { name: "A09 Logging", count: 0, fill: OWASP_COLORS.high },
  { name: "A10 Exceptions", count: 0, fill: OWASP_COLORS.medium },
];

interface SeverityChartProps {
  data?: SimpleChartData;
  /** Données empilées Critical/High/Medium/Low (couleurs maquette) */
  stackedData?: StackedChartData;
}

/**
 * Graphique OWASP : barres simples ou empilées par sévérité (rouge, orange, jaune, bleu).
 */
const CHART_HEIGHT = 340;

export default function SeverityChart({
  data = placeholderData,
  stackedData,
}: SeverityChartProps) {
  const [mounted, setMounted] = useState(false);
  const chartData = stackedData ?? data;
  const isStacked = Boolean(stackedData?.length);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return <div className="h-[340px] w-full min-w-0 animate-pulse rounded bg-(--border)/20" />;
  }

  return (
    <div className="h-[340px] w-full min-w-0" style={{ minWidth: 300 }}>
      <ResponsiveContainer width="100%" height={CHART_HEIGHT} minWidth={300}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 8, right: 8 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis type="number" stroke="var(--text-muted)" fontSize={12} />
          <YAxis
            type="category"
            dataKey="name"
            width={180}
            stroke="var(--text-muted)"
            fontSize={11}
            tick={{ fill: "var(--text-muted)" }}
          />
          <Tooltip
            contentStyle={{
              background: "var(--bg-card)",
              border: "1px solid var(--border)",
              borderRadius: "8px",
            }}
            labelStyle={{ color: "var(--text)" }}
          />
          {isStacked ? (
            <>
              <Bar dataKey="critical" name="Critical" stackId="sev" fill={OWASP_COLORS.critical} radius={[0, 0, 0, 0]} />
              <Bar dataKey="high" name="High" stackId="sev" fill={OWASP_COLORS.high} radius={[0, 0, 0, 0]} />
              <Bar dataKey="medium" name="Medium" stackId="sev" fill={OWASP_COLORS.medium} radius={[0, 0, 0, 0]} />
              <Bar dataKey="low" name="Low" stackId="sev" fill={OWASP_COLORS.low} radius={[0, 4, 4, 0]} />
              <Legend />
            </>
          ) : (
            <>
              <Legend />
              <Bar dataKey="count" name="Issues" radius={[0, 4, 4, 0]}>
                {(chartData as SimpleChartData).map((entry, i) => (
                  <Cell key={i} fill={entry.fill ?? OWASP_COLORS.critical} />
                ))}
              </Bar>
            </>
          )}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
