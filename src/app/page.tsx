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
        <a className="nav-link" href={githubUrl}>GitHub</a>
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
          <UploadForm />
        </div>

        <div className="video-card" aria-label="Product demo placeholder">
          <div className="play-dot" />
          <div>
            <p>VSL demo placeholder</p>
            <span>Explain how the CSV comes back enriched, with confidence and DNS evidence.</span>
          </div>
        </div>
      </section>

      <footer>
        <a href={githubUrl}>Open-source on GitHub</a>
        <span>DNS evidence only. Prefer unknown over incorrect.</span>
      </footer>
    </main>
  );
}
