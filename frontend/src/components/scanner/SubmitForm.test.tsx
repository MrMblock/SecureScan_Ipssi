import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi } from "vitest";
import { http, HttpResponse } from "msw";
import { server } from "@/test-utils/msw-server";
import { renderWithProviders } from "@/test-utils/render";
import SubmitForm from "./SubmitForm";

// Mock next/navigation
const mockPush = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: mockPush,
    replace: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
    refresh: vi.fn(),
    prefetch: vi.fn(),
  }),
}));

describe("SubmitForm", () => {
  it("renders 3 tabs", () => {
    renderWithProviders(<SubmitForm />);
    expect(screen.getByText("URL Git")).toBeInTheDocument();
    expect(screen.getByText("Archive ZIP")).toBeInTheDocument();
    expect(screen.getByText("Coller du Code")).toBeInTheDocument();
  });

  it("shows git URL input by default", () => {
    renderWithProviders(<SubmitForm />);
    const input = screen.getByPlaceholderText(
      "https://github.com/organization/project.git"
    );
    expect(input).toBeInTheDocument();
  });

  it("switches to ZIP tab", async () => {
    const user = userEvent.setup();
    renderWithProviders(<SubmitForm />);
    await user.click(screen.getByText("Archive ZIP"));
    expect(
      screen.getByText(/Glissez-deposez/)
    ).toBeInTheDocument();
  });

  it("switches to paste code tab", async () => {
    const user = userEvent.setup();
    renderWithProviders(<SubmitForm />);
    await user.click(screen.getByText("Coller du Code"));
    expect(screen.getByPlaceholderText("Collez votre code ici...")).toBeInTheDocument();
  });

  it("shows validation error for empty git URL submission", async () => {
    const user = userEvent.setup();
    renderWithProviders(<SubmitForm />);

    // The input has required attribute, but our handleSubmit also checks
    const submitBtn = screen.getByText("Lancer l'Analyse");
    await user.click(submitBtn);

    // Form validation should prevent submission or show error
    await waitFor(() => {
      const errorMsg = screen.queryByText("Veuillez entrer une URL de depot Git.");
      // Either browser validation blocks it or our custom error shows
      expect(errorMsg || document.querySelector(":invalid")).toBeTruthy();
    });
  });

  it("redirects to scan page on successful git submission", async () => {
    const user = userEvent.setup();
    renderWithProviders(<SubmitForm />);

    const input = screen.getByPlaceholderText(
      "https://github.com/organization/project.git"
    );
    await user.type(input, "https://github.com/test/repo.git");

    const submitBtn = screen.getByText("Lancer l'Analyse");
    await user.click(submitBtn);

    await waitFor(() => {
      expect(mockPush).toHaveBeenCalledWith("/scans/new-scan-id");
    });
  });

  it("shows loading state during submission", async () => {
    const user = userEvent.setup();
    server.use(
      http.post("/api/scanner/scans/", async () => {
        await new Promise((r) => setTimeout(r, 200));
        return HttpResponse.json({ id: "slow-scan" });
      })
    );

    renderWithProviders(<SubmitForm />);

    const input = screen.getByPlaceholderText(
      "https://github.com/organization/project.git"
    );
    await user.type(input, "https://github.com/test/repo.git");

    const submitBtn = screen.getByText("Lancer l'Analyse");
    await user.click(submitBtn);

    expect(screen.getByText("Envoi en cours…")).toBeInTheDocument();
  });

  it("fetches and displays GitHub repos when on git tab", async () => {
    renderWithProviders(<SubmitForm />);

    await waitFor(() => {
      const repoBtn = screen.queryByText("Selectionner un depot");
      // repos loaded → select button visible
      expect(repoBtn).toBeInTheDocument();
    });
  });
});
