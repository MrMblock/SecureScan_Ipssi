"use client";

import { useState, useEffect } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface FileEntry {
  file_path: string;
  count: number;
}

interface TopFilesChartProps {
  files: FileEntry[];
}

export default function TopFilesChart({ files }: TopFilesChartProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const data = files.map((f) => ({
    name: f.file_path.split("/").slice(-2).join("/"),
    fullPath: f.file_path,
    count: f.count,
  }));

  if (!mounted) {
    return <div className="h-[280px] w-full animate-pulse rounded bg-(--border)/20" />;
  }

  if (data.length === 0) {
    return (
      <div className="flex h-[280px] w-full items-center justify-center text-sm text-(--text-muted)">
        No vulnerable files found
      </div>
    );
  }

  return (
    <div className="h-[280px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis type="number" stroke="var(--text-muted)" fontSize={11} />
          <YAxis
            type="category"
            dataKey="name"
            width={150}
            stroke="var(--text-muted)"
            fontSize={10}
            tick={{ fill: "var(--text-muted)" }}
          />
          <Tooltip
            contentStyle={{
              background: "var(--bg-card)",
              border: "1px solid var(--border)",
              borderRadius: "8px",
            }}
          />
          <Bar dataKey="count" name="Findings" fill="#f97316" radius={[0, 4, 4, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
