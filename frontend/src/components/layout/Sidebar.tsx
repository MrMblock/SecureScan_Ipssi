"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { useTranslation } from "@/i18n";

interface UserInfo {
  email: string;
  name: string;
  avatar_url: string | null;
}

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const { t } = useTranslation();
  const [user, setUser] = useState<UserInfo | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);

  const navItems = [
    { href: "/dashboard", label: t("app.sidebar.dashboard"), icon: "dashboard" },
    { href: "/projects", label: t("app.sidebar.projects"), icon: "folder" },
    { href: "/scans", label: t("app.sidebar.scans"), icon: "search" },
    { href: "/settings", label: t("app.sidebar.settings"), icon: "settings" },
  ];

  useEffect(() => {
    fetch("/api/accounts/me/", {
      credentials: "include",
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => data && setUser(data))
      .catch((err) => { if (err?.response?.status !== 401) console.error("Failed to fetch user info", err); });
  }, []);

  // Close mobile sidebar on route change
  useEffect(() => {
    setMobileOpen(false);
  }, [pathname]);

  const handleLogout = async () => {
    await fetch("/api/accounts/logout/", {
      method: "POST",
      credentials: "include",
    });
    router.push("/login");
  };

  const sidebarContent = (
    <>
      <div className="flex min-h-18 items-center gap-2.5 border-b border-(--border) px-6 py-5">
        <span
          className="material-symbols-outlined text-xl text-(--text)"
          aria-hidden
        >
          shield
        </span>
        <span className="font-semibold text-(--text)">SecureScan</span>
        {/* Close button on mobile */}
        <button
          type="button"
          className="ml-auto md:hidden rounded p-1 text-(--text-muted) hover:text-(--text)"
          onClick={() => setMobileOpen(false)}
          aria-label="Close menu"
        >
          <span className="material-symbols-outlined text-xl">close</span>
        </button>
      </div>

      <nav className="flex-1 space-y-1 p-4 pt-5">
        {navItems.map((item) => {
          const isActive =
            pathname === item.href || pathname.startsWith(item.href + "/");
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 rounded-lg px-5 py-3 text-sm font-medium transition-colors ${
                isActive
                  ? "bg-(--accent) text-white"
                  : "text-(--text-muted) hover:bg-(--bg-card) hover:text-(--text)"
              }`}
            >
              <span className="material-symbols-outlined text-xl" aria-hidden>
                {item.icon}
              </span>
              {item.label}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-(--border) p-4 pt-6">
        <Link href="/settings" className="mb-3 flex items-center gap-3 group">
          {user?.avatar_url ? (
            <img
              src={user.avatar_url}
              alt="avatar"
              className="h-9 w-9 rounded-full object-cover"
            />
          ) : (
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-white/10">
              <span className="material-symbols-outlined text-lg text-(--text-muted)">
                person
              </span>
            </div>
          )}
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium text-(--text) group-hover:text-(--accent) transition-colors">
              {user?.name || t("app.sidebar.defaultUser")}
            </p>
            <p className="truncate text-xs text-(--text-muted)">
              {user?.email || "..."}
            </p>
          </div>
        </Link>
        <button
          type="button"
          onClick={handleLogout}
          className="w-full rounded-lg border border-(--border) px-4 py-2.5 text-sm text-(--text-muted) hover:bg-(--bg-card) hover:text-(--text) cursor-pointer"
        >
          {t("app.sidebar.logout")}
        </button>
      </div>
    </>
  );

  return (
    <>
      {/* Mobile burger button */}
      <button
        type="button"
        className="fixed left-4 top-3.5 z-50 md:hidden rounded-lg border border-(--border) bg-(--bg-card) p-2 text-(--text-muted) hover:text-(--text)"
        onClick={() => setMobileOpen(true)}
        aria-label="Open menu"
      >
        <span className="material-symbols-outlined text-xl">menu</span>
      </button>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 md:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Mobile sidebar (overlay) */}
      <aside
        className={`fixed left-0 top-0 z-50 flex h-screen w-64 flex-col border-r border-(--border) bg-(--bg-sidebar) transition-transform duration-200 md:hidden ${
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        {sidebarContent}
      </aside>

      {/* Desktop sidebar (always visible) */}
      <aside className="hidden md:flex fixed left-0 top-0 z-30 h-screen w-64 flex-col border-r border-(--border) bg-(--bg-sidebar)">
        {sidebarContent}
      </aside>
    </>
  );
}
