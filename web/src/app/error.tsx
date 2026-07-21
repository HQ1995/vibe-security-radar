"use client";

export default function Error({
  reset,
}: {
  readonly error: Error & { digest?: string };
  readonly reset: () => void;
}) {
  return (
    <main className="mx-auto flex max-w-6xl flex-col items-center justify-center px-4 py-32 text-center sm:px-6">
      <h1 className="text-2xl font-semibold tracking-tight">
        Something went wrong
      </h1>
      <p className="mt-2 max-w-md text-sm text-muted-foreground">
        An unexpected error occurred while rendering this page.
      </p>
      <button
        type="button"
        onClick={reset}
        className="mt-6 inline-flex items-center rounded-lg bg-foreground px-4 py-2 text-sm font-semibold text-background transition-opacity hover:opacity-90"
      >
        Try again
      </button>
    </main>
  );
}
