"use client";

export interface SectionNavItem {
  readonly id: string;
  readonly label: string;
}

interface SectionNavProps {
  readonly items: readonly SectionNavItem[];
}

/**
 * Sticky in-page anchor nav for the CVE detail page.
 * Clicking a chip also opens the target <details> section when collapsed.
 */
export function SectionNav({ items }: SectionNavProps) {
  if (items.length === 0) return null;

  return (
    <nav
      aria-label="On this page"
      className="sticky top-14 z-30 border-b border-border bg-background/85 backdrop-blur"
    >
      <div className="flex items-center gap-1 overflow-x-auto py-2">
        {items.map((item) => (
          <a
            key={item.id}
            href={`#${item.id}`}
            onClick={(event) => {
              event.preventDefault();
              const target = document.getElementById(item.id);
              if (!target) return;
              target.setAttribute("open", "");
              target.scrollIntoView({ behavior: "smooth" });
            }}
            className="shrink-0 rounded-md px-2.5 py-1 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
          >
            {item.label}
          </a>
        ))}
      </div>
    </nav>
  );
}
