import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Reduce JS bundle size
  compiler: {
    // Remove console.error / console.log from production builds
    removeConsole: process.env.NODE_ENV === "production" ? { exclude: ["error"] } : false,
  },
  // Enable React strict mode for better performance warnings during dev
  reactStrictMode: false, // Disabled: double-render causes 2x API calls in dev
  // Speed up image optimisation
  images: {
    minimumCacheTTL: 60,
  },
  // Allow dev access from LAN devices (e.g. mobile testing)
  allowedDevOrigins: ["192.168.0.101", "localhost", "127.0.0.1"],
  // Proxy /api/* and /ws/* requests to the FastAPI backend on port 8000
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://127.0.0.1:8000/api/:path*",
      },
    ];
  },
};

export default nextConfig;
