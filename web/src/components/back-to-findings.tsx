"use client";

import Link from "next/link";
import { useSyncExternalStore } from "react";
import { ArrowLeft } from "lucide-react";

import { rememberedFindingsUrl } from "@/lib/findings-url";

const subscribe = () => () => {};

export function BackToFindings() {
  const href = useSyncExternalStore(
    subscribe,
    rememberedFindingsUrl,
    () => "/cves",
  );
  return (
    <Link
      href={href}
      className="inline-flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
    >
      <ArrowLeft className="h-3.5 w-3.5" />
      Back to findings
    </Link>
  );
}
