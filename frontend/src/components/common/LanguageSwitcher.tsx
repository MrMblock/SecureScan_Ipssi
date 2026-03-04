"use client";

import { useEffect, useState } from "react";
import { useTranslation } from "@/i18n";
import type { Locale } from "@/i18n";

export default function LanguageSwitcher() {
  const { locale, setLocale } = useTranslation();
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  if (!mounted) return <div className="w-[72px] h-[30px]" />;

  const locales: Locale[] = ["fr", "en"];

  return (
    <div className="flex items-center rounded-full border border-white/20 overflow-hidden text-xs">
      {locales.map((l) => (
        <button
          key={l}
          type="button"
          onClick={() => setLocale(l)}
          className={`px-3 py-1.5 font-semibold uppercase transition-colors cursor-pointer ${
            locale === l
              ? "bg-accent text-white"
              : "text-white/50 hover:text-white hover:bg-white/10"
          }`}
        >
          {l}
        </button>
      ))}
    </div>
  );
}
