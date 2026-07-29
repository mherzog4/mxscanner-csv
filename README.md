# MX Scanner CSV

Open-source lead magnet that enriches a prospect CSV with domain-level email security gateway findings.

Upload a CSV of email addresses, scan each unique domain over DNS-over-HTTPS, append MX/SEG/SPF/DMARC findings as new columns, and email the enriched CSV back with Resend.

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

Consumer mailboxes have separate rules — Gmail, Outlook.com / Hotmail, Yahoo / AOL, iCloud, Proton, Zoho, and GMX. They need them: `gmail.com` routes to `gmail-smtp-in.l.google.com` rather than `aspmx`, and `outlook.com` routes to `olc.protection.outlook.com` rather than `mail.protection.outlook.com`, so the business-tenant patterns do not match them. Keeping them distinct is the difference between "this prospect is on a company mail system" and "this is a personal address".

MX evidence assigns every role a rule claims except outbound sender, so a Microsoft 365 tenant counts as both the inbound gateway (EOP) and the mailbox. SPF evidence only ever assigns outbound sender — an include authorizes sending and must not promote a provider to gateway or mailbox on its own.

## Stack

- Next.js App Router
- TypeScript
- DNS-over-HTTPS (Google + Cloudflare, round-robin with failover)
- `@fast-csv/parse` and `@fast-csv/format`
- Resend

Queries go out over DNS-over-HTTPS, spread across Google and Cloudflare by domain so neither provider absorbs the whole scan, with automatic failover to the other on error.

Node's built-in `dns` module is deliberately not used. It sounds like the faster option, but in serverless it resolves through the platform resolver, which rate-limits at roughly 1,000 packets per second per network interface. Measured at the concurrency this scan needs, it managed ~25 domains/sec and returned `EREFUSED`/`ETIMEOUT`, against ~320 domains/sec over DoH with no throttling.

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
NEXT_PUBLIC_GITHUB_URL="https://github.com/your-org/mxscanner-csv"
```

`EMAIL_FROM` defaults to the `gtmreports.com` sender above. If you fork this,
verify your own domain in Resend and override it — Resend rejects a `from`
address on a domain you have not verified.

`EMAIL_REPLY_TO` is optional and unset by default, because `gtmreports.com` is
send-only. A reply-to pointing at a mailbox that bounces is worse than none, so
the report footer directs readers to social links instead. Set it only if you
have a mailbox that accepts mail.

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

- Max file size: 25 MB
- Max rows: 25,000
- Max unique domains: 10,000
- DNS concurrency: 60

These are sized from measurement, not caution. With two DoH resolvers at
concurrency 60, 1,000 domains (14 queries each) resolve in 3-5 seconds, so 10,000
domains fits inside the 300s function budget with room for dead domains that burn
the full 10s abort.

The binding constraints are elsewhere:

- **Resend caps a message at 40 MB after base64.** The route checks the encoded
  size before sending and returns a 413 with instructions rather than letting
  Resend reject a completed scan.
- **Resolver fair use.** 14 queries per domain means a 10,000-domain scan issues
  140,000 queries. Splitting across two providers halves what either one sees.
  Adding a cross-request cache would cut it much further, since public lead
  magnets see the same popular domains repeatedly.
- **The wait is synchronous.** A large scan holds the request open with no
  progress indicator. Past a couple of minutes this wants a background job.

`maxDuration` is 300s, the Fluid Compute default and the Hobby ceiling. Pro and
Enterprise can raise it to 800s.

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
probe list in `src/lib/dns.ts` covers common mailbox and ESP defaults.
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
