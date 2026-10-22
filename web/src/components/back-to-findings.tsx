"use client";

import Link from "next/link";
import { useSyncExternalStore } from "react";

import { rememberedFindingsUrl } from "@/lib/findings-url";

const subscribe = () => () => {};

export function BackToFindings() {
  const href = useSyncExternalStore(
    subscribe,
    rememberedFindingsUrl,
    () => "/cves",
  );
  return (
    <Link href={href} className="text-primary hover:underline">
      Findings
    </Link>
  );
}
