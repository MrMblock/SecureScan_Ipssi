"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { useTranslation } from "@/i18n";
import LanguageSwitcher from "@/components/common/LanguageSwitcher";

interface UserInfo {
  email: string;
  name: string;
  avatar_url: string | null;
}

export default function Header() {
  const pathname = usePathname();
  const { t } = useTranslation();
  const [user, setUser] = useState<UserInfo | null>(null);

  const segmentLabels: Record<string, string> = {
    dashboard: t("app.header.dashboard"),
    projects: t("app.header.projects"),
    scans: t("app.header.scans"),
    reports: t("app.header.reports"),
    settings: t("app.header.settings"),
  };

  useEffect(() => {
    fetch("/api/accounts/me/", {
      credentials: "include",
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => data && setUser(data))
      .catch((err) => { if (err?.response?.status !== 401) console.error("Failed to fetch user info", err); });
  }, []);

  const segments = pathname.split("/").filter(Boolean);
  const breadcrumbItems = [
    { label: t("app.header.home"), href: "/" },
    ...segments.map((segment, i) => ({
      label: segmentLabels[segment] ?? segment,
      href: "/" + segments.slice(0, i + 1).join("/"),
    })),
  ];

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-(--border) bg-(--bg-main) px-4 pl-14 md:pl-10 pr-4 md:pr-8 py-4">
      <nav className="text-sm text-(--text-muted)" aria-label="Fil d'Ariane">
        {breadcrumbItems.map((item, i) => (
          <span key={`${item.href}-${i}`}>
            {i > 0 && <span className="mx-1.5">›</span>}
            {i === breadcrumbItems.length - 1 ? (
              <span>{item.label}</span>
            ) : (
              <Link href={item.href} className="hover:text-(--text)">
                {item.label}
              </Link>
            )}
          </span>
        ))}
      </nav>

      <div className="flex items-center gap-5">
        <LanguageSwitcher />
        <button
          type="button"
          className="relative rounded p-1.5 text-(--text-muted) hover:bg-(--bg-card) hover:text-(--text)"
          aria-label={t("app.header.notifications")}
        >
          <span className="material-symbols-outlined text-xl">
            notifications
          </span>
          <span
            className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full border-2 border-(--bg-main) bg-(--critical)"
            aria-hidden
          />
        </button>

        <Link
          href="/settings"
          className="flex h-8 w-8 items-center justify-center rounded-full overflow-hidden hover:ring-2 hover:ring-(--accent)/50 transition"
        >
          {user?.avatar_url ? (
            <img
              src={user.avatar_url}
              alt="avatar"
              className="h-full w-full object-cover"
            />
          ) : (
            <div className="flex h-full w-full items-center justify-center bg-white/10 text-(--text)">
              <span className="material-symbols-outlined text-xl">person</span>
            </div>
          )}
        </Link>
      </div>
    </header>
  );
}
