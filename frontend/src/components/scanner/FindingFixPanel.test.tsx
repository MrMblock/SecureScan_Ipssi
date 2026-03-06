import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "@/test-utils/msw-server";
import { renderWithProviders } from "@/test-utils/render";
import FindingFixPanel from "./FindingFixPanel";

describe("FindingFixPanel", () => {
  const defaultProps = {
    findingId: "finding-1",
    originalCode: "const unsafe = input;",
  };

  it("shows 'Fix with AI' button initially", () => {
    renderWithProviders(<FindingFixPanel {...defaultProps} />);
    expect(screen.getByText("Corriger avec l'IA")).toBeInTheDocument();
  });

  it("shows loading state when fix is requested", async () => {
    const user = userEvent.setup();
    // Delay the response so we can see loading state
    server.use(
      http.post("/api/scanner/findings/:id/fix/", async () => {
        await new Promise((r) => setTimeout(r, 100));
        return HttpResponse.json({
          fixed_code: "const safe = sanitize(input);",
          fix_explanation: "Sanitized",
          original_code: "const unsafe = input;",
          file_path: "src/app.js",
          line_start: 10,
          cached: false,
        });
      })
    );

    renderWithProviders(<FindingFixPanel {...defaultProps} />);
    await user.click(screen.getByText("Corriger avec l'IA"));
    expect(screen.getByText("Generation du fix IA...")).toBeInTheDocument();
  });

  it("shows tabs after fix is loaded", async () => {
    const user = userEvent.setup();
    renderWithProviders(<FindingFixPanel {...defaultProps} />);
    await user.click(screen.getByText("Corriger avec l'IA"));

    await waitFor(() => {
      expect(screen.getByText("Original")).toBeInTheDocument();
      expect(screen.getByText("Correction Suggeree")).toBeInTheDocument();
    });
  });

  it("switches between original and fix tabs", async () => {
    const user = userEvent.setup();
    renderWithProviders(<FindingFixPanel {...defaultProps} />);
    await user.click(screen.getByText("Corriger avec l'IA"));

    await waitFor(() => {
      expect(screen.getByText("Correction Suggeree")).toBeInTheDocument();
    });

    // Click original tab to show original code
    await user.click(screen.getByText("Original"));

    await waitFor(() => {
      expect(screen.getByText("const unsafe = input;")).toBeInTheDocument();
    });
  });

  it("shows Apply Fix & Create PR button when fix is available", async () => {
    const user = userEvent.setup();
    renderWithProviders(<FindingFixPanel {...defaultProps} isGitRepo />);
    await user.click(screen.getByText("Corriger avec l'IA"));

    await waitFor(() => {
      expect(screen.getByText("Appliquer le Fix & Creer la PR")).toBeInTheDocument();
    });
  });

  it("shows PR link after applying fix", async () => {
    const user = userEvent.setup();
    renderWithProviders(<FindingFixPanel {...defaultProps} isGitRepo />);
    await user.click(screen.getByText("Corriger avec l'IA"));

    await waitFor(() => {
      expect(screen.getByText("Appliquer le Fix & Creer la PR")).toBeInTheDocument();
    });

    await user.click(screen.getByText("Appliquer le Fix & Creer la PR"));

    await waitFor(() => {
      expect(screen.getByText("Voir la PR sur GitHub")).toBeInTheDocument();
    });

    const link = screen.getByText("Voir la PR sur GitHub").closest("a");
    expect(link).toHaveAttribute("href", "https://github.com/user/repo/pull/1");
  });

  it("shows error when fix generation fails", async () => {
    const user = userEvent.setup();
    server.use(
      http.post("/api/scanner/findings/:id/fix/", () => {
        return HttpResponse.json({ detail: "AI service down" }, { status: 500 });
      })
    );

    renderWithProviders(<FindingFixPanel {...defaultProps} />);
    await user.click(screen.getByText("Corriger avec l'IA"));

    await waitFor(() => {
      expect(screen.getByText("AI service down")).toBeInTheDocument();
    });
  });

  it("renders with initialFix prop (skips generate step)", () => {
    const initialFix = {
      fixed_code: "const safe = sanitize(input);",
      fix_explanation: "Sanitized input",
      original_code: "const unsafe = input;",
      file_path: "src/app.js",
      line_start: 10,
      cached: true,
    };

    renderWithProviders(
      <FindingFixPanel {...defaultProps} initialFix={initialFix} />
    );
    expect(screen.getByText("Original")).toBeInTheDocument();
    expect(screen.getByText("Correction Suggeree")).toBeInTheDocument();
  });
});
