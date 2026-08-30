export default function Loading() {
  return (
    <main
      className="mx-auto w-full max-w-[96rem] px-4 py-10 sm:px-6 2xl:px-8"
      aria-busy="true"
      aria-label="Loading case details"
    >
      <span className="sr-only">Loading case details&hellip;</span>
      <div className="animate-pulse space-y-6" aria-hidden="true">
        <div className="h-3 w-24 rounded bg-muted" />
        <div className="h-8 w-3/4 max-w-2xl rounded bg-muted" />
        <div className="h-16 rounded bg-muted/70" />
        <div className="grid items-start gap-8 border-t border-border pt-8 xl:grid-cols-[minmax(0,1fr)_22rem]">
          <div className="space-y-4">
            <div className="h-5 w-40 rounded bg-muted" />
            <div className="h-24 rounded bg-muted/70" />
          </div>
          <div className="h-48 rounded-lg border border-border bg-muted/50" />
        </div>
      </div>
    </main>
  );
}
