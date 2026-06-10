import type { NextConfig } from "next";

// The browser calls this app's own origin under /api/*; the Next server proxies those
// requests to the analyzer. This keeps the browser same-origin (no CORS, no mixed-content)
// and keeps the analyzer URL out of the client bundle.
// NOTE: rewrite destinations are resolved at BUILD time, so ANALYZER_URL must be set when
// `next build` runs (it defaults to the local dev analyzer on :8080).
const ANALYZER_URL = process.env.ANALYZER_URL ?? "http://localhost:8080";

const nextConfig: NextConfig = {
  // Emit a self-contained server bundle for a small production Docker image.
  output: "standalone",
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${ANALYZER_URL}/api/:path*` },
    ];
  },
};

export default nextConfig;
