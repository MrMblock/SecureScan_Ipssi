"use client";

import Sidebar from "./Sidebar";
import Header from "./Header";

interface AppLayoutProps {
  children: React.ReactNode;
}

/**
 * Layout principal de l'application SecureScan.
 * Sidebar à gauche + header (avec breadcrumb et titre dérivés de l'URL) + zone de contenu.
 */
export default function AppLayout({ children }: AppLayoutProps) {
  return (
    <div className="min-h-screen bg-(--bg-main)">
      <Sidebar />
      <div className="md:pl-64">
        <Header />
        <main className="mx-auto max-w-[82.8rem] px-4 py-6 sm:px-6 lg:px-8">
          {children}
        </main>
      </div>
    </div>
  );
}
