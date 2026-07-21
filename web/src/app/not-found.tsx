import Link from "next/link";

export default function NotFound() {
  return (
    <main className="mx-auto flex max-w-6xl flex-col items-center justify-center px-4 py-32 text-center sm:px-6">
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
          className="inline-flex items-center rounded-lg bg-foreground px-4 py-2 text-sm font-semibold text-background transition-opacity hover:opacity-90"
        >
          Home
        </Link>
        <Link
          href="/cves"
          className="inline-flex items-center rounded-lg border border-border px-4 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
        >
          Browse vulnerabilities
        </Link>
      </div>
    </main>
  );
}
