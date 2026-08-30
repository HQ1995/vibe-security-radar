import type { NextConfig } from "next";
import path from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = path.dirname(fileURLToPath(import.meta.url));

const nextConfig: NextConfig = {
  output: "export",
  // Emit <route>/index.html so plain static servers (python http.server) can serve
  // /cves/<id>/ directly; extensionless URLs otherwise 301 into a directory listing.
  trailingSlash: true,
  turbopack: {
    root: appRoot,
  },
  allowedDevOrigins: ["127.0.0.1", "swoop.gtisc.gatech.edu"],
  devIndicators: false,
  images: {
    unoptimized: true,
    remotePatterns: [
      {
        // GitHub owner avatars used by RepoCard
        protocol: "https",
        hostname: "github.com",
        pathname: "/*.png",
      },
    ],
  },
};

export default nextConfig;
