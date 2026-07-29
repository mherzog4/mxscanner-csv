import type { Metadata } from "next";
import { FlowDiagram } from "./flow-diagram";

const title = "How it works — MX SEG Scanner";
const description =
  "One CSV upload replaces thousands of DNS lookups. Walk the pipeline: dedupe to unique domains, scan MX/SPF/DMARC/MTA-STS/DKIM, match 17 gateway fingerprints, get the enriched CSV by email.";

export const metadata: Metadata = {
  title,
  description,
  openGraph: { title, description, type: "article" },
  twitter: { card: "summary", title, description },
};

export default function HowItWorks() {
  const githubUrl = process.env.NEXT_PUBLIC_GITHUB_URL || "#";

  return (
    <main className="page-shell">
      <nav className="topbar" aria-label="Primary navigation">
        <a className="brand" href="/" aria-label="MX Scanner home">
          <span className="brand-mark">MX</span>
          <span>SEG Scanner</span>
        </a>
        <span className="nav-links">
          <a className="nav-link" href="/">Scan a CSV</a>
          <a className="nav-link" href={githubUrl}>GitHub</a>
        </span>
      </nav>

      <header className="flow-header">
        <div className="eyebrow">Open-source lead magnet · MX/SEG Scanner</div>
        <h1>One CSV upload replaces 5,000 DNS lookups</h1>
        <p className="lede">
          Upload a prospect list, and the scanner checks every unique domain&apos;s DNS to find out which inboxes sit
          behind a secure email gateway — Proofpoint, Mimecast, Barracuda, and 14 others — then mails the enriched CSV
          back. Click any step to see what actually runs.
        </p>
      </header>

      <FlowDiagram />

      <footer>
        <a href="/">Scan a CSV</a>
        <span>DNS evidence only. Prefer unknown over incorrect.</span>
      </footer>
    </main>
  );
}
