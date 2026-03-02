import type { Metadata } from "next";
import "./globals.css";
import { I18nProvider } from "@/i18n";

export const metadata: Metadata = {
  title: "SecureScan — Analyse de Securite & Qualite de Code",
  description:
    "Orchestrateur open-source de securite. Scannez vos depots Git avec Semgrep, ESLint, Bandit & plus. Mapping OWASP Top 10, auto-fix et Pull Request automatique.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html suppressHydrationWarning>
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,400,0,0"
          rel="stylesheet"
        />
      </head>
      <body suppressHydrationWarning>
        <I18nProvider>{children}</I18nProvider>
      </body>
    </html>
  );
}
