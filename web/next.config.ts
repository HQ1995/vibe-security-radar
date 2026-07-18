import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  images: {
    remotePatterns: [
      {
        // GitHub owner avatars used by RepoCard
        protocol: "https",
        hostname: "github.com",
        pathname: "/*.png",
      },
    ],
  },
  headers: async () => [
    {
      // HTML pages: revalidate every 10 minutes, serve stale while revalidating
      source: "/((?!_next/).*)",
      headers: [
        {
          key: "Cache-Control",
          value: "public, s-maxage=600, stale-while-revalidate=60",
        },
      ],
    },
  ],
};

export default nextConfig;
