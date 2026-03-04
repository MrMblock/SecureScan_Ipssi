"use client";

/**
 * Page Intégrations : configuration des outils (Semgrep, ESLint, etc.) et CI/CD.
 */
import { useTranslation } from "@/i18n";

export default function IntegrationsPage() {
  const { t } = useTranslation();

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-(--text)">{t("app.integrations.title")}</h1>
      <div className="rounded-xl border border-(--border) bg-(--bg-card) p-8 text-center text-(--text-muted)">
        <p>{t("app.integrations.description")}</p>
      </div>
    </div>
  );
}
