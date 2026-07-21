import { ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

interface SectionProps {
  /** Anchor target id (used by in-page navigation). */
  readonly id?: string;
  readonly title: React.ReactNode;
  /** Optional leading icon, rendered at muted color. */
  readonly icon?: React.ReactNode;
  /** Optional trailing content on the summary row (counts, badges). */
  readonly aside?: React.ReactNode;
  readonly defaultOpen?: boolean;
  /** "md" = page-level section, "sm" = nested/secondary disclosure. */
  readonly size?: "md" | "sm";
  readonly className?: string;
  readonly children: React.ReactNode;
}

/**
 * The single collapsible-section pattern for the whole site.
 * Native <details> so it works without client JS.
 */
export function Section({
  id,
  title,
  icon,
  aside,
  defaultOpen = false,
  size = "md",
  className,
  children,
}: SectionProps) {
  return (
    <details
      id={id}
      open={defaultOpen}
      className={cn("group/section scroll-mt-20", className)}
    >
      <summary
        className={cn(
          "flex cursor-pointer list-none items-center gap-2 rounded-md select-none [&::-webkit-details-marker]:hidden",
          "transition-colors hover:text-foreground",
          size === "md" ? "py-1 text-lg font-semibold" : "py-1.5 text-sm font-medium text-muted-foreground",
        )}
      >
        {icon ? <span className="shrink-0 text-muted-foreground [&_svg]:size-4">{icon}</span> : null}
        <span className="min-w-0 truncate">{title}</span>
        {aside ? <span className="ml-2 shrink-0 text-sm font-normal text-muted-foreground">{aside}</span> : null}
        <ChevronRight className="ml-auto size-4 shrink-0 text-muted-foreground transition-transform group-open/section:rotate-90" />
      </summary>
      <div className={cn(size === "md" ? "mt-4" : "mt-2")}>{children}</div>
    </details>
  );
}
