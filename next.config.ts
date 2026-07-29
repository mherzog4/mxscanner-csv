import { withBotId } from "botid/next/config";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  turbopack: {
    root: process.cwd(),
  },
  // /how-it-works shipped as its own page before the walkthrough moved inline.
  // Keep the old URL alive for anything already linking to it.
  async redirects() {
    return [{ source: "/how-it-works", destination: "/#how-it-works", permanent: true }];
  },
};

export default withBotId(nextConfig);
