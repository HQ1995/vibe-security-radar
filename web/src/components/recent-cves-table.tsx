import Link from "next/link";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import type { CveEntry } from "@/lib/types";

interface RecentCvesTableProps {
  readonly cves: readonly CveEntry[];
}

const SEVERITY_COLORS: Readonly<Record<string, string>> = {
  CRITICAL: "bg-red-600 text-white hover:bg-red-600",
  HIGH: "bg-orange-500 text-white hover:bg-orange-500",
  MEDIUM: "bg-yellow-500 text-black hover:bg-yellow-500",
  LOW: "bg-green-600 text-white hover:bg-green-600",
  UNKNOWN: "bg-zinc-500 text-white hover:bg-zinc-500",
};

function severityBadgeClass(severity: string): string {
  return SEVERITY_COLORS[severity] ?? SEVERITY_COLORS["UNKNOWN"];
}

function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...`;
}

function formatConfidence(confidence: number): string {
  return `${Math.round(confidence * 100)}%`;
}

export function RecentCvesTable({ cves }: RecentCvesTableProps) {
  return (
    <section>
      <h2 className="mb-4 text-xl font-semibold">Recent CVEs</h2>
      <div className="rounded-xl border border-border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>CVE ID</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>AI Tool(s)</TableHead>
              <TableHead className="text-right">Confidence</TableHead>
              <TableHead>Description</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {cves.map((cve) => (
              <TableRow key={cve.id}>
                <TableCell>
                  <Link
                    href={`/cves/${cve.id}`}
                    className="font-mono text-sm text-primary underline-offset-4 hover:underline"
                  >
                    {cve.id}
                  </Link>
                </TableCell>
                <TableCell>
                  <Badge className={severityBadgeClass(cve.severity)}>
                    {cve.severity}
                  </Badge>
                </TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {cve.ai_tools.join(", ")}
                </TableCell>
                <TableCell className="text-right font-mono text-sm">
                  {formatConfidence(cve.confidence)}
                </TableCell>
                <TableCell
                  className="max-w-xs text-sm text-muted-foreground"
                  title={cve.description}
                >
                  {truncate(cve.description, 80)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </section>
  );
}
