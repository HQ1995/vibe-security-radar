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
      <div className="page-container flex h-14 items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <Link
            href="/"
            aria-label="Vibe Security Radar home"
            className="flex min-w-0 items-center gap-2"
          >
            <svg
              viewBox="0 0 64 64"
              aria-hidden="true"
              className="h-6 w-6 shrink-0"
            >
              <rect width="64" height="64" rx="14" fill="#2357e6" />
              <g fill="none" stroke="#fff" strokeLinecap="round">
                <circle
                  cx="32"
                  cy="32"
                  r="21"
                  strokeWidth="3.5"
                  strokeOpacity=".4"
                />
                <circle
                  cx="32"
                  cy="32"
                  r="12"
                  strokeWidth="3.5"
                  strokeOpacity=".7"
                />
                <path d="M32 32 47 17" strokeWidth="4" />
              </g>
              <circle cx="32" cy="32" r="4" fill="#fff" />
              <circle cx="42.5" cy="42" r="4" fill="#ffb020" />
            </svg>
            <span className="hidden truncate text-sm font-semibold tracking-[-0.02em] min-[400px]:inline sm:hidden">
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
                className={`whitespace-nowrap rounded-full px-2.5 py-1.5 text-xs transition-colors sm:px-3.5 sm:text-sm ${
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
