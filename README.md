# MX Scanner CSV

Open-source lead magnet that enriches a prospect CSV with domain-level email security gateway findings.

Upload a CSV of email addresses, scan each unique domain through Google Public DNS, append MX/SEG/SPF/DMARC findings as new columns, and email the enriched CSV back with Resend.

## What It Detects

- MX records
- Secure Email Gateway provider, when detectable
- SEG confidence score
- Mailbox provider
- Outbound senders from SPF includes
- SPF status and record
- DMARC status, policy, and record
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
EMAIL_FROM="MX Scanner <reports@example.com>"
NEXT_PUBLIC_GITHUB_URL="https://github.com/your-org/mxscanner-csv"
```

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
```

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
