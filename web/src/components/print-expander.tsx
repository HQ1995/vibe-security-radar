"use client";

import { useEffect } from "react";

export function PrintExpander() {
  useEffect(() => {
    const opened = new Set<HTMLDetailsElement>();
    const expand = () => {
      for (const element of document.querySelectorAll("details:not([open])")) {
        const details = element as HTMLDetailsElement;
        opened.add(details);
        details.open = true;
      }
    };
    const restore = () => {
      for (const details of opened) details.open = false;
      opened.clear();
    };
    window.addEventListener("beforeprint", expand);
    window.addEventListener("afterprint", restore);
    return () => {
      window.removeEventListener("beforeprint", expand);
      window.removeEventListener("afterprint", restore);
    };
  }, []);
  return null;
}
