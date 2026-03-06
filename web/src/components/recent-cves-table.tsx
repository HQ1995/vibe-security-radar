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
import { ToolIcon } from "@/components/tool-icon";
import { severityBadgeClass } from "@/lib/constants";
import { LanguageBadge } from "@/components/language-badge";
import { VerifiedBadge } from "@/components/verified-badge";
import type { CveEntry } from "@/lib/types";

interface RecentCvesTableProps {
  readonly cves: readonly CveEntry[];
}

export function RecentCvesTable({ cves }: RecentCvesTableProps) {
  return (
    <section>
      <h2 className="mb-4 text-xl font-semibold">Recent Vulnerabilities</h2>
      <div className="rounded-xl border border-border overflow-x-auto">
        <Table className="table-fixed w-full min-w-[940px]">
          <TableHeader>
            <TableRow>
              <TableHead className="w-[180px]">ID</TableHead>
              <TableHead className="w-[100px]">Severity</TableHead>
              <TableHead className="w-[72px]">Tools</TableHead>
              <TableHead className="w-[120px]">Language</TableHead>
              <TableHead className="w-[200px] text-center">Verified</TableHead>
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
                <TableCell>
                  <div className="flex items-center gap-1.5">
                    {cve.ai_tools.map((tool) => (
                      <ToolIcon key={tool} tool={tool} size={18} />
                    ))}
                  </div>
                </TableCell>
                <TableCell>
                  {cve.languages.length === 0 ? (
                    <span className="text-muted-foreground/40 text-xs">—</span>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {cve.languages.map((lang) => (
                        <LanguageBadge key={lang} language={lang} />
                      ))}
                    </div>
                  )}
                </TableCell>
                <TableCell className="text-center">
                  <VerifiedBadge verifiedBy={cve.verified_by} />
                </TableCell>
                <TableCell
                  className="text-sm text-muted-foreground truncate"
                  title={cve.description}
                >
                  {cve.description}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </section>
  );
}
