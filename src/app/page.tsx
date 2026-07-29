import { FlowDiagram } from "./flow-diagram";
import { UploadForm } from "./upload-form";

export default function Home() {
  const githubUrl = process.env.NEXT_PUBLIC_GITHUB_URL || "#";

  return (
    <main className="page-shell">
      <nav className="topbar" aria-label="Primary navigation">
        <a className="brand" href="/" aria-label="MX Scanner home">
          <span className="brand-mark">MX</span>
          <span>SEG Scanner</span>
        </a>
        <span className="nav-links">
          <a className="nav-link" href="#how-it-works">How it works</a>
          <a className="nav-link" href={githubUrl}>GitHub</a>
        </span>
      </nav>

      <section className="hero">
        <div className="hero-copy">
          <div className="eyebrow">Open-source prospect enrichment</div>
          <h1>Find the email gateways hiding in your lead list.</h1>
          <p className="lede">Upload a prospect CSV and get it back with MX, SEG, SPF, and DMARC findings appended.</p>
          <div className="hero-proof" aria-label="Detected provider examples">
            <span>Proofpoint</span>
            <span>Mimecast</span>
            <span>Barracuda</span>
            <span>Microsoft 365</span>
            <span>Google Workspace</span>
          </div>
        </div>

        <UploadForm />
      </section>

      <section className="flow-section" id="how-it-works">
        <div className="eyebrow">How it works</div>
        <h2>One CSV upload replaces 5,000 DNS lookups</h2>
        <p className="lede">
          Every unique domain gets checked against public DNS to find out which inboxes sit behind a secure email
          gateway. Click any step to see what actually runs.
        </p>
        <FlowDiagram />
      </section>

      <footer>
        <span>
          <a href="#how-it-works">How it works</a> · <a href={githubUrl}>Open-source on GitHub</a> · built by{" "}
          <a href="https://mattherzog.xyz">Matt Herzog</a>
        </span>
        <span>DNS evidence only. Prefer unknown over incorrect.</span>
      </footer>
    </main>
  );
}
