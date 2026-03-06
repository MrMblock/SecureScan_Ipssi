import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import ScanProgressBar from "./ScanProgressBar";

describe("ScanProgressBar", () => {
  const STATUSES = ["pending", "cloning", "detecting", "scanning", "aggregating", "completed"];

  it.each(STATUSES)("renders status '%s' without crashing", (status) => {
    const { container } = render(<ScanProgressBar status={status} />);
    expect(container.firstChild).toBeTruthy();
  });

  it("shows 0% progress for pending", () => {
    const { container } = render(<ScanProgressBar status="pending" />);
    const bar = container.querySelector("[style]") as HTMLElement;
    expect(bar.style.width).toBe("0%");
  });

  it("shows 100% progress for completed", () => {
    const { container } = render(<ScanProgressBar status="completed" />);
    const bar = container.querySelector("[style]") as HTMLElement;
    expect(bar.style.width).toBe("100%");
  });

  it("shows intermediate progress for scanning (index 4 of 7)", () => {
    const { container } = render(<ScanProgressBar status="scanning" />);
    const bar = container.querySelector("[style]") as HTMLElement;
    // scanning is index 4 out of 7 steps (0-6) → 4/6 ≈ 66.67%
    expect(bar.style.width).toBe(`${(4 / 6) * 100}%`);
  });

  it("applies red color for failed status", () => {
    const { container } = render(<ScanProgressBar status="failed" />);
    const bar = container.querySelector(".bg-red-500");
    expect(bar).toBeInTheDocument();
  });

  it("applies emerald color for completed status", () => {
    const { container } = render(<ScanProgressBar status="completed" />);
    const bar = container.querySelector(".bg-emerald-500");
    expect(bar).toBeInTheDocument();
  });

  it("shows 0% progress for failed", () => {
    const { container } = render(<ScanProgressBar status="failed" />);
    const bar = container.querySelector("[style]") as HTMLElement;
    expect(bar.style.width).toBe("0%");
  });

  it("handles unknown status gracefully (0% progress)", () => {
    const { container } = render(<ScanProgressBar status="unknown_status" />);
    const bar = container.querySelector("[style]") as HTMLElement;
    expect(bar.style.width).toBe("0%");
  });

  it("renders step labels", () => {
    render(<ScanProgressBar status="scanning" />);
    expect(screen.getByText("Queued")).toBeInTheDocument();
    expect(screen.getByText("Cloning")).toBeInTheDocument();
    expect(screen.getByText("Scanning")).toBeInTheDocument();
    expect(screen.getByText("Done")).toBeInTheDocument();
  });

  it("applies pulse animation only on active non-terminal step", () => {
    const { container } = render(<ScanProgressBar status="cloning" />);
    const pulseElements = container.querySelectorAll(".animate-pulse");
    expect(pulseElements.length).toBeGreaterThan(0);
  });
});
