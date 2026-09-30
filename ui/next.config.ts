import type { NextConfig } from "next";

/**
 * The console runs on a machine that may not be the gateway.
 *
 * On the gateway itself it is reachable over the LAN; on a developer's laptop
 * it is not exposed at all, because the useful workflow there is `next dev`
 * against a locally-built `thn`. Binding to all interfaces is a deliberate
 * decision rather than a default, and it is the only place this file touches
 * the network.
 */
const nextConfig: NextConfig = {
  reactStrictMode: true,

  // The UI shells out to the Go binary rather than reimplementing any of its
  // logic. Nothing is fetched from the browser, so there is nothing to expose
  // to a content security policy, and the app has no client-side data layer of
  // its own.
  poweredByHeader: false,
};

export default nextConfig;
