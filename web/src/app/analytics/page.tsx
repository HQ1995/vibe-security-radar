"use client";

import { useEffect } from "react";

export default function AnalyticsPage() {
  useEffect(() => {
    window.location.replace("/#disclosure-trend");
  }, []);

  return (
    <main className="mx-auto max-w-[96rem] px-4 py-16 text-sm text-muted-foreground">
      <p>
        Trends now live on the homepage.{" "}
        <a href="/#disclosure-trend" className="text-primary hover:underline">
          Open the disclosure chart
        </a>
        .
      </p>
    </main>
  );
}
