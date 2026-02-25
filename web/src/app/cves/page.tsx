import { getCves } from "@/lib/data";
import { CveListClient } from "@/components/cve-list";

export const metadata = {
  title: "Vulnerability Database - Vibe Security Radar",
  description: "All vulnerabilities with detected AI coding tool involvement",
};

export default function CvesPage() {
  const data = getCves();

  return (
    <main className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
      <div className="space-y-2 mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Vulnerability Database</h1>
        <p className="text-muted-foreground">
          All vulnerabilities with detected AI coding tool involvement
        </p>
      </div>
      <CveListClient cves={data.cves} />
    </main>
  );
}
