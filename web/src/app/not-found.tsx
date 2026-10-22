import Link from "next/link";
import { Search } from "lucide-react";

export default function NotFound() {
  return (
    <main className="page-container py-20 sm:py-28">
      <div className="max-w-xl">
        <p className="text-sm text-muted-foreground">404</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-[-0.03em]">
          Page not found
        </h1>
        <p className="mt-3 leading-7 text-muted-foreground">
          The page does not exist or has moved. Findings are listed under
          their maintainer advisory ID; search for a CVE, GHSA or repository
          to find the current page.
        </p>
        <form action="/cves/" method="get" className="mt-6 flex gap-2">
          <label className="relative min-w-0 flex-1">
            <span className="sr-only">Search findings</span>
            <Search
              aria-hidden="true"
              className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
            />
            <input
              type="search"
              name="q"
              placeholder="CVE, GHSA, repository or keyword"
              className="h-10 w-full rounded-md border border-input bg-card pl-9 pr-3 text-sm text-foreground outline-none focus:border-primary focus:ring-2 focus:ring-primary/15"
            />
          </label>
          <button
            type="submit"
            className="h-10 shrink-0 rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90"
          >
            Search
          </button>
        </form>
        <p className="mt-4 flex flex-wrap gap-x-4 gap-y-1 text-sm">
          <Link href="/" className="text-primary hover:underline">
            Home
          </Link>
          <Link href="/cves" className="text-primary hover:underline">
            All findings
          </Link>
          <Link href="/about" className="text-primary hover:underline">
            How we verify
          </Link>
        </p>
      </div>
    </main>
  );
}
