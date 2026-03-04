import { render, screen, act } from "@testing-library/react";
import { describe, it, expect, beforeEach } from "vitest";
import I18nProvider, { type Locale } from "./I18nProvider";
import { useTranslation } from "./useTranslation";

// Helper component that exposes translation functions
function TestComponent({ testKey }: { testKey: string }) {
  const { t, locale, setLocale } = useTranslation();
  return (
    <div>
      <span data-testid="result">{t(testKey)}</span>
      <span data-testid="locale">{locale}</span>
      <button onClick={() => setLocale("en" as Locale)}>Switch EN</button>
      <button onClick={() => setLocale("fr" as Locale)}>Switch FR</button>
    </div>
  );
}

function renderWithI18n(testKey: string) {
  return render(
    <I18nProvider>
      <TestComponent testKey={testKey} />
    </I18nProvider>
  );
}

describe("useTranslation + I18nProvider", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("defaults to French locale", () => {
    renderWithI18n("common.loading");
    expect(screen.getByTestId("locale").textContent).toBe("fr");
    expect(screen.getByTestId("result").textContent).toBe("Chargement...");
  });

  it("translates a key in French", () => {
    renderWithI18n("common.error");
    expect(screen.getByTestId("result").textContent).toBe("Erreur");
  });

  it("switches to English and translates", async () => {
    renderWithI18n("common.loading");
    await act(async () => {
      screen.getByText("Switch EN").click();
    });
    expect(screen.getByTestId("locale").textContent).toBe("en");
    expect(screen.getByTestId("result").textContent).toBe("Loading...");
  });

  it("returns the key itself for missing keys", () => {
    renderWithI18n("this.key.does.not.exist");
    expect(screen.getByTestId("result").textContent).toBe("this.key.does.not.exist");
  });

  it("persists locale to localStorage", async () => {
    renderWithI18n("common.loading");
    await act(async () => {
      screen.getByText("Switch EN").click();
    });
    expect(localStorage.getItem("locale")).toBe("en");
  });

  it("reads locale from localStorage on mount", () => {
    localStorage.setItem("locale", "en");
    renderWithI18n("common.loading");
    // After useEffect runs, it should pick up "en"
    // The initial render is "fr", then effect sets "en"
    // We need to wait for the effect
    expect(screen.getByTestId("result").textContent).toBe("Loading...");
  });

  it("throws when used outside I18nProvider", () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => {
      render(<TestComponent testKey="test" />);
    }).toThrow("useTranslation must be used within an I18nProvider");
    consoleError.mockRestore();
  });
});
