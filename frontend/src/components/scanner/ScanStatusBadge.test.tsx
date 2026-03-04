import { screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import ScanStatusBadge from "./ScanStatusBadge";
import { renderWithProviders } from "@/test-utils/render";

describe("ScanStatusBadge", () => {
  const STATUS_CONFIGS: [string, string, string][] = [
    // [status, expectedBg, expectedFrLabel]
    ["pending", "bg-slate-700", "En attente"],
    ["cloning", "bg-blue-900", "Clonage"],
    ["detecting", "bg-yellow-900", "Detection des Langages"],
    ["scanning", "bg-blue-900", "Analyse"],
    ["aggregating", "bg-blue-900", "Agregation"],
    ["completed", "bg-green-900", "Termine"],
    ["failed", "bg-red-900", "Echoue"],
  ];

  it.each(STATUS_CONFIGS)(
    "renders '%s' with correct bg class and translated label",
    (status, bgClass, frLabel) => {
      renderWithProviders(<ScanStatusBadge status={status} />);
      const badge = screen.getByText(frLabel);
      expect(badge).toBeInTheDocument();
      expect(badge.className).toContain(bgClass);
    }
  );

  it("falls back to raw status for unknown status", () => {
    renderWithProviders(<ScanStatusBadge status="weird_status" />);
    const badge = screen.getByText("weird_status");
    expect(badge).toBeInTheDocument();
    // Should use fallback slate styling
    expect(badge.className).toContain("bg-slate-700");
  });

  it("renders as a span element with badge classes", () => {
    renderWithProviders(<ScanStatusBadge status="completed" />);
    const badge = screen.getByText("Termine");
    expect(badge.tagName).toBe("SPAN");
    expect(badge.className).toContain("rounded-full");
    expect(badge.className).toContain("uppercase");
  });
});
