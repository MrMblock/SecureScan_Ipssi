"use client";

import {
  createContext,
  useCallback,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import fr from "./locales/fr.json";
import en from "./locales/en.json";

export type Locale = "fr" | "en";

const translations: Record<Locale, any> = { fr, en };

export interface I18nContextValue {
  locale: Locale;
  setLocale: (l: Locale) => void;
  t: (key: string) => string;
}

export const I18nContext = createContext<I18nContextValue | null>(null);

function resolve(obj: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((acc, part) => {
    if (acc && typeof acc === "object" && part in (acc as Record<string, unknown>)) {
      return (acc as Record<string, unknown>)[part];
    }
    return undefined;
  }, obj);
}

export default function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>("fr");

  // Read from localStorage on mount
  useEffect(() => {
    const stored = localStorage.getItem("locale");
    if (stored === "en" || stored === "fr") {
      setLocaleState(stored);
    }
  }, []);

  // Persist + update html lang
  useEffect(() => {
    localStorage.setItem("locale", locale);
    document.documentElement.lang = locale;
  }, [locale]);

  const setLocale = useCallback((l: Locale) => {
    setLocaleState(l);
  }, []);

  const t = useCallback(
    (key: string): string => {
      const value = resolve(translations[locale], key);
      if (typeof value === "string") return value;
      // Fallback to French, then to key itself
      const fallback = resolve(translations.fr, key);
      if (typeof fallback === "string") return fallback;
      return key;
    },
    [locale],
  );

  return (
    <I18nContext.Provider value={{ locale, setLocale, t }}>
      {children}
    </I18nContext.Provider>
  );
}
