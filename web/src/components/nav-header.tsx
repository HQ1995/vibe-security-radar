"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV_LINKS = [
  { href: "/cves", label: "Vulnerabilities" },
  { href: "/analytics", label: "Analytics" },
  { href: "/about", label: "About" },
] as const;

export function NavHeader() {
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-50 border-b border-border bg-background/90 backdrop-blur-lg">
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between gap-2 px-4 sm:px-6">
        <Link
          href="/"
          className="shrink-0 whitespace-nowrap text-xs font-semibold uppercase tracking-wide text-foreground sm:text-sm"
        >
          Vibe Security Radar
        </Link>
        <nav aria-label="Primary" className="flex items-center gap-0.5 sm:gap-1">
          {NAV_LINKS.map((link) => {
            const isActive =
              pathname === link.href || pathname.startsWith(link.href + "/");
            return (
              <Link
                key={link.href}
                href={link.href}
                aria-current={isActive ? "page" : undefined}
                className={`rounded-md px-2 py-1.5 text-xs transition-colors sm:px-3 sm:text-sm ${
                  isActive
                    ? "text-foreground font-medium"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {link.label}
              </Link>
            );
          })}
        </nav>
      </div>
    </header>
  );
}
