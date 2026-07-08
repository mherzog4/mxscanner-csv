# PRD: CSV-Based Prospect Email Security Gateway Detector

## Overview

Build a free, open-source engineering-as-marketing tool that lets users upload a CSV of prospect email addresses, detects the email security gateway and mail infrastructure for each prospect domain, appends the findings as new columns to the original CSV, and emails the enriched CSV back to the submitter using Resend.

The primary value is accurate SEG detection for prospect domains: Proofpoint, Mimecast, Barracuda, Microsoft Defender / Exchange Online Protection, Google Workspace, Cisco Secure Email, and similar providers.

The initial product should be intentionally simple: one intake form, a placeholder for a VSL/demo, CSV upload, and a confirmation state.

## Primary Goal

The main goal is to identify which Secure Email Gateway (SEG), mailbox provider, and outbound email platforms are associated with each prospect domain in an uploaded CSV.

The tool should help users:

- Segment prospect lists by email security provider.
- Understand deliverability and filtering risk by domain.
- Identify prospects protected by enterprise-grade email security.
- Enrich lead lists with domain-level email infrastructure data.
- Receive a usable enriched CSV without needing to copy results manually.

## Target Users

- Cold email operators and agencies.
- Growth marketers auditing lead lists.
- Sales teams segmenting prospect accounts.
- Founders building outbound campaigns.
- Developers and open-source users who want a self-hosted DNS enrichment tool.

## Core User Flow

1. User visits the landing page.
2. User enters their email address.
3. User uploads a CSV containing prospect emails.
4. User submits the form.
5. System validates the CSV and extracts email domains.
6. System deduplicates domains.
7. System scans each unique domain using DNS records.
8. System maps findings back onto every original CSV row.
9. System appends MX, SEG, SPF, and DMARC findings as new CSV columns.
10. System sends the enriched CSV back to the submitter via Resend.

## MVP Scope

### Landing / Intake Page

The first screen should be extremely simple.

Required elements:

- Headline explaining the value.
- Short subheadline.
- Placeholder block for a VSL/demo video.
- Email input for report delivery.
- CSV upload field.
- Submit button.
- Short explanation of what the scan detects.
- Open-source notice or GitHub link placeholder.

Suggested headline:

```text
Upload a prospect CSV. Get it back enriched with each domain's email security gateway.
```

Suggested subheadline:

```text
Detect Proofpoint, Mimecast, Barracuda, Microsoft 365, Google Workspace, and other email infrastructure from prospect domains.
```

### CSV Upload

The app should accept a `.csv` file containing email addresses.

Supported email column names:

- `email`
- `Email`
- `email_address`
- `work_email`
- `business_email`
- `primary_email`

If no known email column is found, the system should attempt to detect email-like values across columns.

CSV requirements:

- Extract valid email addresses.
- Extract domains from valid emails.
- Normalize domains to lowercase.
- Deduplicate domains before DNS scanning.
- Preserve malformed or missing email rows in the returned CSV.
- Return a clear validation error if no valid email addresses are found.

Suggested MVP limits:

- Max file size: 1 MB.
- Max rows: 5,000.
- Max unique domains: 500.
- Max concurrent DNS requests: 10-25.

## DNS Scanning Approach

Use Google Public DNS JSON API over HTTPS for the MVP.

Base endpoint:

```text
https://dns.google/resolve
```

Recommended query format:

```text
https://dns.google/resolve?name={domain}&type={recordType}&edns_client_subnet=0.0.0.0/0
```

Use `edns_client_subnet=0.0.0.0/0` to reduce client subnet leakage.

### Required DNS Queries Per Domain

- `MX` for inbound mail routing and SEG detection.
- `TXT` for SPF and outbound sender detection.
- `_dmarc.{domain}` `TXT` for DMARC policy detection.
- Optional `A` / `AAAA` for basic domain validity checks.

### Google DNS API Decision

Use Google Public DNS JSON API for MVP.

Reasons:

- No resolver infrastructure needed.
- Simple HTTPS interface.
- Works well in serverless environments.
- Easy to parse JSON responses.
- Supports DNSSEC-related response metadata.

Building a native DNS scanner is not recommended for MVP unless API latency, volume, or rate limits become a bottleneck.

Future versions may add a native resolver for higher throughput and better control.

## SEG Detection

SEG detection is the core product requirement. Mapping accuracy matters more than a generic MX health check.

The scanner should identify providers such as:

- Proofpoint
- Proofpoint Essentials
- Mimecast
- Barracuda
- Microsoft Defender / Exchange Online Protection
- Google Workspace / Gmail
- Cisco Secure Email / IronPort
- Sophos
- Fortinet FortiMail
- Trend Micro Email Security
- Cloudflare Area 1
- Check Point / Avanan, where detectable
- Zix / AppRiver
- Other vendors discoverable through MX, TXT, SPF, and related DNS patterns

### Classification Model

The scanner must distinguish between inbound security gateways, mailbox providers, and outbound senders.

```ts
type EmailSecurityClassification = {
  inboundProvider: ProviderDetection | null;
  mailboxProvider: ProviderDetection | null;
  outboundSenders: ProviderDetection[];
  securityGateway: ProviderDetection | null;
};
```

Definitions:

- `inboundProvider`: provider handling inbound MX.
- `mailboxProvider`: likely mailbox host, such as Microsoft 365 or Google Workspace.
- `outboundSenders`: platforms authorized in SPF, such as SendGrid, Mailchimp, HubSpot, Salesforce, or Mailgun.
- `securityGateway`: SEG vendor if detected, such as Proofpoint, Mimecast, Barracuda, Cisco, or similar.

This distinction is required to avoid falsely labeling outbound senders as security gateways.

### Provider Detection Output

Each provider detection should include:

- Provider name.
- Provider category.
- Confidence level.
- Evidence source.
- Matching DNS record.
- Explanation.

Example:

```json
{
  "domain": "example.com",
  "detectedProvider": "Proofpoint",
  "confidence": "high",
  "evidence": [
    {
      "recordType": "MX",
      "record": "mxa-002a1b01.gslb.pphosted.com",
      "reason": "MX hostname matches Proofpoint pphosted.com pattern"
    }
  ]
}
```

### Confidence Levels

- `high`: direct MX hostname or strong TXT evidence identifies the provider.
- `medium`: multiple weaker signals point to the provider.
- `low`: one indirect or ambiguous signal exists.
- `unknown`: no provider confidently identified.

Accuracy principle:

Prefer `unknown` over an overconfident incorrect detection.

## Initial Provider Mapping Rules

### MX-Based Detection

MX records are the strongest signal for inbound SEG and mailbox detection.

| Provider | Category | MX / Hostname Patterns |
|---|---|---|
| Proofpoint | SEG | `pphosted.com`, `proofpoint.com` |
| Proofpoint Essentials | SEG | `ppe-hosted.com` |
| Mimecast | SEG | `mimecast.com`, `mimecastprotect.com` |
| Barracuda | SEG | `ess.barracudanetworks.com`, `barracudanetworks.com` |
| Microsoft 365 / EOP | Mailbox / SEG | `mail.protection.outlook.com` |
| Google Workspace | Mailbox | `aspmx.l.google.com`, `googlemail.com`, Google MX patterns |
| Cisco Secure Email / IronPort | SEG | `iphmx.com`, `ironport.com`, Cisco mail patterns |
| Sophos | SEG | `sophos.com`, `sophosxl.net` |
| Fortinet FortiMail | SEG | `fortimail`, `fortinet.com` |
| Trend Micro Email Security | SEG | `trendmicro.com`, `trendmicro.eu`, `in.tmes.trendmicro.com` |
| Cloudflare Area 1 | SEG | `area1.cloudflare.net`, `mx.cloudflare.net` |
| Zix / AppRiver | SEG | `appriver.com`, `zixcorp.com` |

### SPF/TXT-Based Supporting Detection

TXT and SPF records should support provider detection but usually should not override MX evidence.

Useful SPF include patterns:

| Provider | Category | SPF / TXT Patterns |
|---|---|---|
| Mimecast | SEG / outbound | `include:_netblocks.mimecast.com`, `mimecast.com` |
| Barracuda | SEG / outbound | `barracudanetworks.com` |
| Microsoft 365 | Mailbox / outbound | `include:spf.protection.outlook.com` |
| Google Workspace | Mailbox / outbound | `include:_spf.google.com` |
| Cisco | SEG / outbound | `iphmx.com`, Cisco-related includes |
| SendGrid | Outbound sender | `sendgrid.net` |
| Mailgun | Outbound sender | `mailgun.org` |
| Mailchimp | Outbound sender | `servers.mcsv.net`, `mailchimp.com` |
| HubSpot | Outbound sender | `hubspotemail.net` |
| Salesforce | Outbound sender | `salesforce.com`, Salesforce email includes |

Important distinction:

- MX records usually indicate inbound filtering or mailbox hosting.
- SPF records usually indicate who is authorized to send mail.
- Do not classify a domain as using a SEG only because its SPF record includes a sender platform.

## Accuracy Rules

- MX evidence outranks SPF evidence for SEG detection.
- SPF sender platforms must not be labeled as SEGs.
- Microsoft and Google may be mailbox providers, security gateways, or both depending on evidence.
- If MX points to a known SEG and SPF points to Microsoft or Google, classify the SEG as inbound security gateway and Microsoft or Google only as supporting mailbox/outbound context when evidence supports it.
- If multiple MX providers are present, report all evidence and select the highest-confidence primary provider.
- Preserve raw DNS evidence in the report for auditability.
- Unknown is an acceptable result.
- Do not overclaim provider detection from ambiguous records.

## Detection Rule Registry

Provider mappings should live in a maintainable registry, not scattered throughout scanner logic.

Suggested rule shape:

```ts
type ProviderRule = {
  id: string;
  name: string;
  categories: Array<"seg" | "mailbox" | "outbound_sender" | "hosting">;
  mxPatterns?: string[];
  txtPatterns?: string[];
  spfIncludePatterns?: string[];
  confidence: "high" | "medium" | "low";
};
```

The registry should be easy for open-source contributors to update with additional provider mappings and corrections.

## Supporting Deliverability Checks

Although SEG detection is the main goal, the scanner should also return basic email DNS health information.

### MX Checks

- MX present.
- MX missing.
- MX query error.
- Raw MX records.

### SPF Checks

- SPF present.
- SPF missing.
- Multiple SPF records.
- Raw SPF record.
- Outbound sender includes.

### DMARC Checks

- DMARC present.
- DMARC missing.
- DMARC policy: `none`, `quarantine`, or `reject`.
- Raw DMARC record.

Suggested severity:

- No MX records: `critical`.
- SPF missing: `warning`.
- Multiple SPF records: `critical`.
- DMARC missing: `warning`.
- DMARC `p=none`: `warning`.
- DMARC `p=quarantine` or `p=reject`: `good`.
- DNS query failure: `unknown`.

## Enriched CSV Output

The emailed report must include the original submitted CSV with MX and email security findings appended as new columns.

The goal is that the user uploads a lead/prospect list and receives the same list back enriched with domain-level MX/SEG intelligence.

### Enriched CSV Behavior

The system must:

- Preserve all original rows.
- Preserve all original columns.
- Preserve original row order.
- Append new columns to the right side of the CSV.
- Avoid mutating existing cell values.
- Quote values safely for CSV compatibility.
- Handle commas, semicolons, quotes, and newlines in DNS records.
- Use blank values where no data exists.
- Keep rows with invalid or missing emails.
- Add row-level scan status or error values for invalid rows.

### Domain-Level Caching

Since scans are domain-level, not person-level:

1. Extract all valid domains from the input CSV.
2. Deduplicate domains.
3. Scan each unique domain once.
4. Map domain findings back onto every matching row.
5. Append findings to each row.
6. Generate enriched CSV.
7. Email enriched CSV back to the submitter.

### MVP Appended Headers

```text
mx_domain
mx_status
mx_records
detected_seg_provider
detected_seg_confidence
detected_mailbox_provider
detected_outbound_senders
spf_status
spf_record
dmarc_status
dmarc_policy
dmarc_record
mx_scan_notes
mx_scan_error
```

### Optional Future Headers

```text
mx_primary_host
mx_provider_evidence
seg_evidence_record_type
seg_evidence_record
dnssec_ad
mta_sts_status
tls_rpt_status
bimi_status
```

### Example Enriched CSV

Original input:

```csv
first_name,last_name,email,company
Jane,Doe,jane@example.com,Example Inc
Bob,Smith,bob@acme.com,Acme
```

Returned enriched CSV:

```csv
first_name,last_name,email,company,mx_domain,mx_status,mx_records,detected_seg_provider,detected_seg_confidence,detected_mailbox_provider,detected_outbound_senders,spf_status,spf_record,dmarc_status,dmarc_policy,dmarc_record,mx_scan_notes,mx_scan_error
Jane,Doe,jane@example.com,Example Inc,example.com,present,"10 mxa-001.pphosted.com; 10 mxb-001.pphosted.com",Proofpoint,high,Unknown,"",present,"v=spf1 include:_spf.example.com -all",present,reject,"v=DMARC1; p=reject; rua=mailto:dmarc@example.com","MX hostname matched pphosted.com",
Bob,Smith,bob@acme.com,Acme,acme.com,present,"1 aspmx.l.google.com",None,unknown,Google Workspace,"SendGrid",present,"v=spf1 include:_spf.google.com include:sendgrid.net ~all",missing,,,"No SEG detected; Google Workspace MX detected",
```

## Email Report via Resend

After scanning, send an email to the submitter using Resend.

The email should include:

- Short HTML summary of the scan.
- Total rows processed.
- Total valid emails found.
- Total unique domains scanned.
- SEG provider breakdown.
- Number of unknown or unclassified domains.
- Short disclaimer that detection is DNS-evidence-based and confidence-scored.
- Enriched CSV attachment.

Attachment filename format:

```text
mx-seg-enriched-{original-filename}-{YYYY-MM-DD}.csv
```

Example summary:

```text
Scanned 418 unique domains.

Detected email security providers:
- Microsoft 365 / EOP: 142 domains
- Google Workspace: 96 domains
- Proofpoint: 38 domains
- Mimecast: 24 domains
- Barracuda: 11 domains
- Unknown: 107 domains
```

## Data Model

### Scan Request

```ts
type ScanRequest = {
  id: string;
  submitterEmail: string;
  originalFileName: string;
  totalRows: number;
  totalEmailsFound: number;
  uniqueDomainsFound: number;
  status: "pending" | "processing" | "completed" | "failed";
  createdAt: string;
  completedAt?: string;
};
```

### Provider Detection

```ts
type ProviderDetection = {
  providerId: string;
  providerName: string;
  category: "seg" | "mailbox" | "outbound_sender" | "hosting";
  confidence: "high" | "medium" | "low" | "unknown";
  evidence: Array<{
    recordType: "MX" | "TXT" | "SPF" | "DMARC";
    record: string;
    reason: string;
  }>;
};
```

### Domain Scan Result

```ts
type DomainScanResult = {
  domain: string;
  mx: {
    status: "present" | "missing" | "error";
    records: string[];
  };
  spf: {
    status: "present" | "missing" | "multiple" | "error";
    records: string[];
  };
  dmarc: {
    status: "present" | "missing" | "error";
    policy?: "none" | "quarantine" | "reject";
    record?: string;
  };
  classification: EmailSecurityClassification;
  dnssec?: {
    ad: boolean;
  };
  notes: string[];
  error?: string;
};
```

## UX Requirements

The interface should stay minimal and low-friction.

Sections:

1. Hero.
2. VSL/demo placeholder.
3. Upload form.
4. What the scanner detects.
5. Open-source footer.

No account system or dashboard is required for MVP.

## Security, Privacy, and Abuse Prevention

Because this is public and free:

- Validate uploaded file type and size.
- Do not execute uploaded content.
- Do not store uploaded CSVs permanently in MVP.
- Do not store raw email addresses after processing unless explicitly configured.
- Avoid logging raw submitted emails.
- Store API keys only in environment variables.
- Rate limit submissions.
- Consider CAPTCHA if abuse appears.
- Limit max unique domains per scan.
- Limit DNS request concurrency.
- Sanitize all report output.

Privacy position:

```text
Uploaded CSVs are processed transiently to extract domains and generate an enriched report. The service does not need to retain the uploaded file after the report is sent.
```

## Open Source Requirements

The project should be easy to self-host and contribute to.

Required files:

- `README.md`
- `.env.example`
- `LICENSE`
- Basic contribution instructions

The README should explain:

- What the tool does.
- How SEG detection works.
- How to run locally.
- Required environment variables.
- Resend setup.
- Google Public DNS API usage.
- How to add provider mappings.
- Privacy and data retention assumptions.

## Out of Scope for MVP

- User accounts.
- Billing.
- Persistent scan history.
- Google Sheets OAuth integration.
- Real-time progress dashboard.
- Shareable hosted reports.
- Full inbox placement testing.
- Blacklist checks.
- SMTP-level probing.
- Advanced DKIM selector discovery.
- Native DNS resolver infrastructure.
- Queue dashboard.

Note: Users may call the returned file a spreadsheet or sheet, but MVP should email an enriched CSV attachment rather than integrate with Google Sheets.

## Future Enhancements

- Native DNS resolver for higher performance.
- Queue-based background jobs.
- Downloadable report links.
- PDF summary report.
- DKIM selector discovery.
- BIMI checks.
- MTA-STS checks.
- TLS-RPT checks.
- Blacklist checks.
- Provider mapping test fixtures.
- Confidence calibration using known domains.
- Community-maintained provider registry.
- Admin analytics for lead magnet conversion.
- API endpoint for programmatic enrichment.
- Docker deployment.
- Optional Google Sheets export.

## Success Metrics

- Upload-to-report completion rate.
- Average scan completion time.
- SEG detection coverage rate.
- Unknown provider rate.
- Email open rate for delivered reports.
- Reply/conversion rate from report CTA.
- GitHub stars, forks, and provider-rule contributions.

## Acceptance Criteria

- A user can submit their email and upload a CSV.
- The app extracts valid email domains from the CSV.
- Duplicate domains are scanned only once.
- The app checks MX, SPF, and DMARC records.
- The app detects SEG providers from DNS evidence.
- The app distinguishes SEG providers from mailbox providers and outbound senders.
- The app includes confidence levels and evidence for provider detection.
- The app preserves all original CSV rows and columns.
- The app appends MX, SEG, SPF, and DMARC columns to the CSV.
- Rows with invalid emails are preserved and marked with an error.
- The app emails the enriched CSV attachment via Resend.
- The email body includes a provider breakdown summary.
- Invalid CSVs show a clear error.
- API keys and secrets are configured through environment variables.
- The provider detection registry is easy to update for open-source contributors.
