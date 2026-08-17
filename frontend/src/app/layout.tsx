import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "NIDS Dashboard — Network Intrusion Detection System",
  description:
    "Real-time AI-powered network intrusion detection, threat monitoring, and predictive security analytics dashboard.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body suppressHydrationWarning>{children}</body>
    </html>
  );
}
