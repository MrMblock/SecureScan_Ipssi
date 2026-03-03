"use client";

import { useState, useEffect } from "react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from "recharts";

const COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

interface DonutData {
  name: string;
  value: number;
  color: string;
}

interface SeverityDonutChartProps {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export default function SeverityDonutChart({
  critical,
  high,
  medium,
  low,
}: SeverityDonutChartProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const data: DonutData[] = [
    { name: "Critical", value: critical, color: COLORS.critical },
    { name: "High", value: high, color: COLORS.high },
    { name: "Medium", value: medium, color: COLORS.medium },
    { name: "Low", value: low, color: COLORS.low },
  ].filter((d) => d.value > 0);

  if (!mounted) {
    return <div className="h-[280px] w-full animate-pulse rounded bg-(--border)/20" />;
  }

  if (data.length === 0) {
    return (
      <div className="flex h-[280px] w-full items-center justify-center text-sm text-(--text-muted)">
        No vulnerabilities found
      </div>
    );
  }

  return (
    <div className="h-[280px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={100}
            paddingAngle={3}
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: "var(--bg-card)",
              border: "1px solid var(--border)",
              borderRadius: "8px",
            }}
          />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
