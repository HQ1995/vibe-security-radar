import Link from "next/link";

export default function NotFound() {
  return (
    <main className="page-container flex flex-col items-center justify-center py-32 text-center">
      <p className="font-mono text-sm text-muted-foreground">404</p>
      <h1 className="mt-2 text-2xl font-semibold tracking-tight">
        Page not found
      </h1>
      <p className="mt-2 max-w-md text-sm text-muted-foreground">
        The page you are looking for does not exist or may have been moved.
      </p>
      <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
        <Link
          href="/"
          className="inline-flex h-10 items-center rounded-md bg-primary px-4 text-sm font-semibold text-primary-foreground transition-colors hover:bg-primary/90"
        >
          Home
        </Link>
        <Link
          href="/cves"
          className="inline-flex h-10 items-center rounded-md border border-border bg-card px-4 text-sm font-semibold transition-colors hover:border-foreground/40"
        >
          Browse findings
        </Link>
      </div>
    </main>
  );
}
