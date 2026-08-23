"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV_LINKS = [
  { href: "/cves", label: "Findings" },
  { href: "/#disclosure-trend", label: "Trends" },
  { href: "/about", label: "How we verify" },
] as const;

export function NavHeader() {
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-50 border-b border-border/70 bg-background/80 backdrop-blur-xl">
      <div className="mx-auto flex h-16 w-full max-w-[96rem] items-center justify-between gap-3 px-4 sm:px-6 2xl:px-8 min-[1920px]:max-w-[112rem] min-[2400px]:max-w-[128rem]">
        <div className="flex min-w-0 items-center gap-3">
          <Link
            href="/"
            aria-label="Vibe Security Radar home"
            className="min-w-0"
          >
            <span className="truncate text-sm font-semibold tracking-[-0.02em] sm:hidden">
              VSR
            </span>
            <span className="hidden truncate text-sm font-semibold tracking-[-0.02em] sm:inline">
              Vibe Security Radar
            </span>
          </Link>
        </div>
        <nav
          aria-label="Primary"
          className="flex items-center gap-0.5 sm:gap-1"
        >
          {NAV_LINKS.map((link) => {
            const isActive =
              !link.href.includes("#") &&
              (pathname === link.href || pathname.startsWith(link.href + "/"));
            return (
              <Link
                key={link.href}
                href={link.href}
                aria-current={isActive ? "page" : undefined}
                className={`rounded-full px-2.5 py-1.5 text-xs transition-colors sm:px-3.5 sm:text-sm ${
                  isActive
                    ? "bg-primary/10 font-medium text-primary"
                    : "text-muted-foreground hover:bg-muted/60 hover:text-foreground"
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
