"use client";

import { useState, useEffect } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface TimelineEntry {
  date: string;
  score: number;
}

interface ScanTimelineChartProps {
  scans: { created_at: string; security_score: number | null }[];
}

export default function ScanTimelineChart({ scans }: ScanTimelineChartProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const data: TimelineEntry[] = scans
    .filter((s) => s.security_score !== null)
    .map((s) => ({
      date: new Date(s.created_at).toLocaleDateString(),
      score: s.security_score!,
    }))
    .reverse();

  if (!mounted) {
    return <div className="h-[280px] w-full animate-pulse rounded bg-(--border)/20" />;
  }

  if (data.length === 0) {
    return (
      <div className="flex h-[280px] w-full items-center justify-center text-sm text-(--text-muted)">
        No scan history yet
      </div>
    );
  }

  return (
    <div className="h-[280px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis dataKey="date" stroke="var(--text-muted)" fontSize={11} />
          <YAxis domain={[0, 100]} stroke="var(--text-muted)" fontSize={11} />
          <Tooltip
            contentStyle={{
              background: "var(--bg-card)",
              border: "1px solid var(--border)",
              borderRadius: "8px",
            }}
          />
          <Area
            type="monotone"
            dataKey="score"
            name="Security Score"
            stroke="#3b82f6"
            fill="#3b82f6"
            fillOpacity={0.15}
            strokeWidth={2}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
