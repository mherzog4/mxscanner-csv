"use client";

import { useState, type ReactNode } from "react";

type StepKey = keyof typeof STEPS;

const STEPS = {
  upload: {
    title: "Upload CSV + your email",
    meta: "input · one form, two fields",
    body: (
      <>
        Any prospect export works — Apollo, Clay, HubSpot, a raw list. You give the CSV and the address the finished
        report should be delivered to. Nothing is stored server-side.
      </>
    ),
    code: "POST /api/scan\n  file:  prospects.csv  (≤25 MB)\n  email: you@company.com",
  },
  guard: {
    title: "Bot + abuse checks",
    meta: "route.ts · runs before anything else",
    body: (
      <>
        Vercel BotID blocks automated requests, then two durable rate limits: 5 scans per IP per hour and 3 reports per
        recipient email per day. Free tools get scraped; this one defends itself.
      </>
    ),
    code: "checkBotId()\ncheckRateLimit(`scan:${ip}`, 5, 1h)\ncheckRateLimit(`report:${email}`, 3, 24h)",
  },
  parse: {
    title: "Parse + validate CSV",
    meta: "fast-csv · headers auto-detected",
    body: (
      <>
        Streams the CSV, caps it at 25,000 rows, and finds the email column automatically — first by header name (
        <code>email</code>, <code>work_email</code>…), then by sniffing which column actually contains addresses.
      </>
    ),
    code: "EMAIL_COLUMNS = {email, email_address,\n  work_email, business_email, ...}\n// fallback: regex-sniff every column",
  },
  dedupe: {
    title: "Dedupe to unique domains",
    meta: "the trick that makes it fast",
    body: (
      <>
        25,000 prospects usually share far fewer companies. DNS is per-domain, not per-person — so the scanner
        extracts each address&apos;s domain, lowercases it, and scans the unique set once (max 500).
      </>
    ),
    code: "acme.com   × 40 rows → 1 lookup\nglobex.io  × 12 rows → 1 lookup\n...",
  },
  dns: {
    title: "DNS scan per domain",
    meta: "2 DoH resolvers · 60 workers · 10s timeout",
    body: (
      <>
        Fourteen queries fire in parallel for every domain over DNS-over-HTTPS: MX, TXT (for SPF),{" "}
        <code>_dmarc</code>, <code>_mta-sts</code>, <code>_smtp._tls</code>, <code>default._bimi</code>, and eight
        common DKIM selectors. A worker pool of 20 keeps the whole batch to a couple of minutes. A dead domain
        can&apos;t hang the run — it times out and gets marked as an error row.
      </>
    ),
    code: "GET dns.google/resolve?name=acme.com&type=MX\nGET dns.google/resolve?name=acme.com&type=TXT\nGET dns.google/resolve?name=_dmarc.acme.com&type=TXT\nGET dns.google/resolve?name=_mta-sts.acme.com&type=TXT\nGET dns.google/resolve?name=selector1._domainkey.acme.com&type=TXT",
  },
  rules: {
    title: "Match 24 provider rules",
    meta: "provider-rules.ts · pattern table, no AI",
    body: (
      <>
        Each provider is a set of fingerprints: MX hostnames, TXT strings, SPF includes. A hit classifies the domain as
        SEG, mailbox provider, and/or outbound sender — with a confidence level and the exact DNS record kept as
        evidence. Consumer inboxes get their own rules, so Gmail and Outlook.com rows are counted separately from
        Workspace and 365 tenants.
      </>
    ),
    code: "mimecast:\n  mx:  mimecast.com\n  spf: _netblocks.mimecast.com\n  confidence: high",
  },
  gate: {
    title: "Gated or clear?",
    meta: "classification · per domain",
    body: (
      <>
        The only question that changes your send order: does a secure email gateway sit in front of this inbox? A SEG
        match means a filtering appliance opens your email before a human ever does.
      </>
    ),
    code: "if (classification.securityGateway)\n  → gated bucket\nelse\n  → clear bucket",
  },
  gated: {
    title: "Gated inbox",
    meta: "SEG detected · send these last",
    body: (
      <>
        Proofpoint, Mimecast, Barracuda, Cisco IronPort, Sophos, Trend Micro, Cloudflare Area 1 and more. These filters
        score sender reputation hard — hit them early with a cold domain and you train them to junk you.
      </>
    ),
    code: "detected_seg_provider:   Proofpoint\ndetected_seg_confidence: high\nmx_primary_host:         mxa-001.pphosted.com",
  },
  clear: {
    title: "Clear inbox",
    meta: "no SEG detected · send these first",
    body: (
      <>
        Plain Google Workspace or Microsoft 365 without a third-party gateway, or a domain nothing matched. Your easiest
        deliverability — warm your domain here and earn replies before attempting the gated bucket.
      </>
    ),
    code: "detected_seg_provider:      (empty)\ndetected_mailbox_provider:  Google Workspace",
  },
  enrich: {
    title: "Append 24 new columns",
    meta: "csv-enrichment.ts · original rows untouched",
    body: (
      <>
        Every row keeps its original columns and gains the scan: SEG provider + confidence, mailbox provider, outbound
        senders, primary MX host, SPF, DMARC, MTA-STS, TLS-RPT, BIMI, discovered DKIM selectors, DNSSEC, and the raw DNS
        evidence. Cells are sanitized against CSV formula injection before writing.
      </>
    ),
    code: "detected_seg_provider, detected_seg_confidence,\nmx_primary_host, spf_status, dmarc_policy,\nmta_sts_status, tls_rpt_status, bimi_status,\ndkim_status, dkim_selectors, dnssec_ad, ...",
  },
  send: {
    title: "Email the CSV back",
    meta: "Resend · attachment + summary",
    body: (
      <>
        The enriched CSV arrives as an attachment with a summary: total rows, unique domains, a count per detected
        provider, and a deliverability rollup. No dashboard to log into — the deliverable lands where you already work.
      </>
    ),
    code: "mx-seg-enriched-prospects-2026-07-29.csv\n\nProofpoint: 84 · Mimecast: 31\nGoogle Workspace: 210 · Unknown: 96\n312/421 domains enforce DMARC",
  },
  done: {
    title: "Segmented send list",
    meta: "terminal · the whole point",
    body: (
      <>
        Sort by <code>detected_seg_provider</code> and the checklist becomes automatic: clear inboxes in the first sends
        while your reputation builds, gated inboxes once replies are flowing. Pre-flight check done.
      </>
    ),
    code: "sort → clear first, gated last\nsend → easy wins → earned reputation\n     → then take your shot at the SEGs",
  },
} satisfies Record<string, { title: string; meta: string; body: ReactNode; code: string }>;

type NodeProps = {
  k: StepKey;
  active: StepKey;
  onSelect: (key: StepKey) => void;
  className?: string;
  children: ReactNode;
};

function FlowNode({ k, active, onSelect, className, children }: NodeProps) {
  const step = STEPS[k];
  return (
    <g
      className={`flow-node ${className ?? ""} ${active === k ? "active" : ""}`}
      role="button"
      tabIndex={0}
      aria-pressed={active === k}
      aria-label={step.title}
      onClick={() => onSelect(k)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onSelect(k);
        }
      }}
    >
      {children}
    </g>
  );
}

export function FlowDiagram() {
  const [active, setActive] = useState<StepKey>("upload");
  const step = STEPS[active];
  const nodeProps = { active, onSelect: setActive };

  return (
    <div className="flow-layout">
      <div>
        <div className="flow-canvas">
          <svg className="flow" viewBox="0 0 620 1010" role="group" aria-label="Scan pipeline, step by step">
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path className="arrow-head" d="M0,0 L10,5 L0,10 z" />
              </marker>
              <marker id="arrow-bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path className="arrow-head bad" d="M0,0 L10,5 L0,10 z" />
              </marker>
              <marker id="arrow-ok" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path className="arrow-head ok" d="M0,0 L10,5 L0,10 z" />
              </marker>
            </defs>

            <path className="edge" d="M310,56 L310,92" />
            <path className="edge" d="M310,140 L310,176" />
            <path className="edge" d="M310,224 L310,260" />
            <path className="edge" d="M310,308 L310,344" />
            <path className="edge" d="M310,392 L310,428" />
            <path className="edge" d="M310,476 L310,514" />
            {/* Branch colors follow the destination bucket, not yes/no: a SEG
                match is the hard-to-reach side, so it inherits the danger hue. */}
            <path className="edge no" d="M268,546 C200,546 160,570 155,616" />
            <text className="lbl no" x="150" y="560">SEG match</text>
            <path className="edge yes" d="M352,546 C420,546 460,570 465,616" />
            <text className="lbl yes" x="410" y="560">no SEG found</text>
            <path className="edge" d="M155,664 C160,710 240,730 288,738" />
            <path className="edge" d="M465,664 C460,710 380,730 332,738" />
            <path className="edge" d="M310,786 L310,822" />
            <path className="edge" d="M310,870 L310,908" />

            <FlowNode k="upload" className="term" {...nodeProps}>
              <rect x="210" y="12" width="200" height="44" />
              <text x="310" y="32" textAnchor="middle">Upload CSV + your email</text>
              <text className="sub" x="310" y="47" textAnchor="middle">up to 25,000 prospect rows</text>
            </FlowNode>

            <FlowNode k="guard" {...nodeProps}>
              <rect x="210" y="92" width="200" height="48" />
              <text x="310" y="112" textAnchor="middle">Bot + abuse checks</text>
              <text className="sub" x="310" y="128" textAnchor="middle">BotID · rate limits per IP + email</text>
            </FlowNode>

            <FlowNode k="parse" {...nodeProps}>
              <rect x="210" y="176" width="200" height="48" />
              <text x="310" y="196" textAnchor="middle">Parse + validate CSV</text>
              <text className="sub" x="310" y="212" textAnchor="middle">auto-detects the email column</text>
            </FlowNode>

            <FlowNode k="dedupe" {...nodeProps}>
              <rect x="210" y="260" width="200" height="48" />
              <text x="310" y="280" textAnchor="middle">Dedupe to unique domains</text>
              <text className="sub" x="310" y="296" textAnchor="middle">25,000 rows → ≤1,500 domains</text>
            </FlowNode>

            <FlowNode k="dns" {...nodeProps}>
              <rect x="210" y="344" width="200" height="48" />
              <text x="310" y="364" textAnchor="middle">DNS scan per domain</text>
              <text className="sub" x="310" y="380" textAnchor="middle">MX · SPF · DMARC · MTA-STS · DKIM</text>
            </FlowNode>

            <FlowNode k="rules" {...nodeProps}>
              <rect x="210" y="428" width="200" height="48" />
              <text x="310" y="448" textAnchor="middle">Match 24 provider rules</text>
              <text className="sub" x="310" y="464" textAnchor="middle">SEG · mailbox · outbound senders</text>
            </FlowNode>

            <FlowNode k="gate" className="gate" {...nodeProps}>
              <path d="M310,514 L352,546 L310,578 L268,546 Z" />
              <text x="310" y="550" textAnchor="middle">gated?</text>
            </FlowNode>

            <FlowNode k="gated" className="bad" {...nodeProps}>
              <rect x="55" y="616" width="200" height="48" />
              <text x="155" y="636" textAnchor="middle">Gated inbox</text>
              <text className="sub" x="155" y="652" textAnchor="middle">Proofpoint, Mimecast, Barracuda…</text>
            </FlowNode>

            <FlowNode k="clear" className="ok" {...nodeProps}>
              <rect x="365" y="616" width="200" height="48" />
              <text x="465" y="636" textAnchor="middle">Clear inbox</text>
              <text className="sub" x="465" y="652" textAnchor="middle">Google Workspace, M365, unknown</text>
            </FlowNode>

            <FlowNode k="enrich" {...nodeProps}>
              <rect x="210" y="738" width="200" height="48" />
              <text x="310" y="758" textAnchor="middle">Append 24 new columns</text>
              <text className="sub" x="310" y="774" textAnchor="middle">every row, evidence included</text>
            </FlowNode>

            <FlowNode k="send" {...nodeProps}>
              <rect x="210" y="822" width="200" height="48" />
              <text x="310" y="842" textAnchor="middle">Email the CSV back</text>
              <text className="sub" x="310" y="858" textAnchor="middle">Resend · summary + attachment</text>
            </FlowNode>

            <FlowNode k="done" className="ok term" {...nodeProps}>
              <rect x="200" y="908" width="220" height="44" />
              <text x="310" y="928" textAnchor="middle">Segmented send list</text>
              <text className="sub" x="310" y="943" textAnchor="middle">easy inboxes first, gated ones last</text>
            </FlowNode>
          </svg>
        </div>

        <div className="flow-legend">
          <span><i className="chip" /> pipeline step</span>
          <span><i className="chip gate" /> classification</span>
          <span><i className="chip bad" /> gated (SEG detected)</span>
          <span><i className="chip ok" /> clear / terminal</span>
        </div>
      </div>

      <aside className="flow-panel" aria-live="polite">
        <div className="hint">Click a step in the chart</div>
        <h3>{step.title}</h3>
        <div className="meta">{step.meta}</div>
        <p>{step.body}</p>
        <pre>{step.code}</pre>
      </aside>
    </div>
  );
}
