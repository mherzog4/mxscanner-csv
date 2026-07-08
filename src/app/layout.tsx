import type { Metadata } from "next";
import { BotIdClient } from "botid/client";
import { Geist, Geist_Mono } from "next/font/google";
import "./styles.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

const title = "MX SEG Scanner";
const description = "Upload a prospect CSV and receive SEG-enriched MX findings by email. Detects Proofpoint, Mimecast, Barracuda, and 14 other email gateways from public DNS.";

export const metadata: Metadata = {
  title,
  description,
  openGraph: {
    title,
    description,
    type: "website",
    siteName: title,
  },
  twitter: {
    card: "summary",
    title,
    description,
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable}`}>
      <head>
        <BotIdClient protect={[{ path: "/api/scan", method: "POST" }]} />
      </head>
      <body>{children}</body>
    </html>
  );
}
