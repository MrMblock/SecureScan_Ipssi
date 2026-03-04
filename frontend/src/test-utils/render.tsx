import { render, type RenderOptions } from "@testing-library/react";
import type { ReactElement } from "react";
import I18nProvider from "@/i18n/I18nProvider";

function Providers({ children }: { children: React.ReactNode }) {
  return <I18nProvider>{children}</I18nProvider>;
}

export function renderWithProviders(
  ui: ReactElement,
  options?: Omit<RenderOptions, "wrapper">
) {
  return render(ui, { wrapper: Providers, ...options });
}
