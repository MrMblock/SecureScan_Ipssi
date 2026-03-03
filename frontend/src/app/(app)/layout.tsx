import AppLayout from "@/components/layout/AppLayout";
import AuthGuard from "@/components/auth/AuthGuard";

/**
 * Layout pour toutes les pages de l'app (Dashboard, Scans, Vulnerabilities, etc.).
 * Applique la sidebar et le header sur chaque page du groupe (app).
 */
export default function AppGroupLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <AuthGuard>
      <AppLayout>{children}</AppLayout>
    </AuthGuard>
  );
}
