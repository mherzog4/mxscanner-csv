# MX Scanner CSV

Open-source lead magnet that enriches a prospect CSV with domain-level email security gateway findings.

Upload a CSV of email addresses, scan each unique domain through Google Public DNS, append MX/SEG/SPF/DMARC findings as new columns, and email the enriched CSV back with Resend.

## What It Detects

- MX records and the primary (lowest-preference) MX host
- Secure Email Gateway provider, when detectable
- SEG confidence score and the DNS record it came from
- Mailbox provider
- Outbound senders from SPF includes
- SPF status and record
- DMARC status, policy, and record
- MTA-STS, TLS-RPT, and BIMI policy presence
- DKIM selectors found on a common-selector probe
- DNSSEC authenticated-data flag
- Scan notes and errors

Initial provider mappings include Proofpoint, Proofpoint Essentials, Mimecast, Barracuda, Microsoft 365 / EOP, Google Workspace, Cisco Secure Email / IronPort, Sophos, Fortinet, Trend Micro, Cloudflare Area 1, Zix / AppRiver, SendGrid, Mailgun, Mailchimp, HubSpot, and Salesforce.

## Stack

- Next.js App Router
- TypeScript
- Google Public DNS JSON API
- `@fast-csv/parse` and `@fast-csv/format`
- Resend

The MVP uses Google Public DNS because it is simple, serverless-friendly, and fast enough for a public lead magnet. Native DNS resolution can be added later if API throughput becomes the bottleneck.

## Local Setup

```bash
npm install
cp .env.example .env
npm run dev
```

Set these environment variables:

```bash
RESEND_API_KEY=re_...
EMAIL_FROM="MX SEG Scanner <reports@gtmreports.com>"
EMAIL_REPLY_TO="matt@gtmreports.com"
NEXT_PUBLIC_GITHUB_URL="https://github.com/your-org/mxscanner-csv"
```

`EMAIL_FROM` and `EMAIL_REPLY_TO` default to the `gtmreports.com` values above.
If you fork this, verify your own domain in Resend and override both — Resend
rejects a `from` address on a domain you have not verified.

## Usage

1. Open `http://localhost:3000`.
2. Enter the email address where the report should be sent.
3. Upload a CSV with an email column.
4. Submit the form.
5. Receive an enriched CSV attachment by email.

Supported email column names:

- `email`
- `Email`
- `email_address`
- `work_email`
- `business_email`
- `primary_email`

If none of those headers exist, the scanner attempts to detect email-like values in any column.

## Limits

MVP limits are intentionally conservative:

- Max file size: 1 MB
- Max rows: 5,000
- Max unique domains: 500
- DNS concurrency: 20

## Enriched CSV Columns

The output preserves every original row and column, then appends:

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
mx_primary_host
mx_provider_evidence
seg_evidence_record_type
seg_evidence_record
dnssec_ad
mta_sts_status
tls_rpt_status
bimi_status
dkim_status
dkim_selectors
```

## DNS Queries Per Domain

Each unique domain gets 14 DNS-over-HTTPS queries, all issued in parallel:

```text
MX                            inbound routing + SEG detection
TXT                           SPF and provider TXT fingerprints
_dmarc.{domain}               DMARC policy
_mta-sts.{domain}             MTA-STS policy presence
_smtp._tls.{domain}           TLS-RPT reporting
default._bimi.{domain}        BIMI record
{selector}._domainkey.{domain}  8 common DKIM selectors
```

DKIM selectors cannot be enumerated from DNS — they can only be guessed — so the
probe list in `src/lib/dns-google.ts` covers common mailbox and ESP defaults.
A missing selector means "not found on a common name", not "no DKIM".

## Provider Rules

Provider mappings live in `src/lib/provider-rules.ts`.

Rules are evidence-based and should prefer `unknown` over false positives. MX evidence is stronger than SPF evidence for SEG classification because SPF often identifies outbound senders rather than inbound filtering.

See `CONTRIBUTING.md` for provider-rule contribution guidance.

## Verification

```bash
npm run typecheck
npm run test
npm run build
```

## Privacy

The app processes uploaded CSVs transiently. It does not persist uploaded files or the email addresses contained in them. Resend receives the submitter email and the enriched CSV attachment so it can deliver the report, and the submitter email is stored as a contact in a Resend audience for product follow-up (when `RESEND_AUDIENCE_ID` is configured).
