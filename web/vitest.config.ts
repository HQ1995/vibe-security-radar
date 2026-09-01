import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  test: {
    globals: true,
    testTimeout: 30000,
    // CI runners are slow; the full-corpus reachability test alone runs 3-8s.
    // A 30s budget keeps a slow runner from turning into a flaky CI failure.
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
});
