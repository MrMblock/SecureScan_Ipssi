import { render, screen, act } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import SeverityChart, { type SimpleChartData, type StackedChartData } from "./SeverityChart";

describe("SeverityChart", () => {
  it("renders without crashing on initial render", () => {
    const { container } = render(<SeverityChart />);
    // Component renders either skeleton or chart depending on timing
    expect(container.firstChild).toBeTruthy();
  });

  it("renders chart after mount effect runs", async () => {
    const { container } = render(<SeverityChart />);

    // After mount, useEffect sets mounted=true
    await act(async () => {});

    // Skeleton should be gone
    const skeleton = container.querySelector(".animate-pulse");
    expect(skeleton).not.toBeInTheDocument();

    // Chart container should be present
    const chartContainer = container.querySelector(".recharts-responsive-container");
    expect(chartContainer).toBeInTheDocument();
  });

  it("renders with custom simple data", async () => {
    const data: SimpleChartData = [
      { name: "SQL Injection", count: 5, fill: "#ff0000" },
      { name: "XSS", count: 3, fill: "#ff9900" },
    ];

    const { container } = render(<SeverityChart data={data} />);

    await act(async () => {});

    expect(container.querySelector(".recharts-responsive-container")).toBeInTheDocument();
  });

  it("renders stacked data when provided", async () => {
    const stackedData: StackedChartData = [
      { name: "A01 Access Control", critical: 3, high: 2, medium: 1, low: 0 },
      { name: "A05 Injection", critical: 1, high: 4, medium: 2, low: 1 },
    ];

    const { container } = render(<SeverityChart stackedData={stackedData} />);

    await act(async () => {});

    expect(container.querySelector(".recharts-responsive-container")).toBeInTheDocument();
  });

  it("uses placeholder data by default", async () => {
    const { container } = render(<SeverityChart />);

    await act(async () => {});

    // Default data has 10 OWASP categories
    expect(container.querySelector(".recharts-responsive-container")).toBeInTheDocument();
  });
});
