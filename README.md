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
- Max unique domains: 3,500 (1,500 with DKIM probing)
- DNS concurrency: 60

The domain cap is set from **production** measurement, and the first number was
wrong. A local benchmark showed ~320 domains/sec against the DoH resolvers, so the cap
was initially set to 10,000. A deployed function then failed to finish 5,000 domains
inside the 300s limit — under ~17/sec effective — and delivered nothing at all. Public
resolvers throttle datacenter egress far harder than a residential connection, and the
local run also benefited from warm parent-zone NS caches. Do not trust laptop DNS
throughput numbers for serverless.

The scan also carries a 240s internal budget. Domains not reached before it expires
come back marked (`mx_scan_error` says the budget was exhausted) so a long run degrades
into a partial report instead of being killed mid-flight with nothing delivered.

The binding constraints are elsewhere:

- **Resend caps a message at 40 MB after base64.** The route checks the encoded
  size before sending and returns a 413 with instructions rather than letting
  Resend reject a completed scan.
- **Resolver fair use.** 14 queries per domain means a 10,000-domain scan issues
  140,000 queries. Splitting across two providers halves what either one sees, and
  the domain cache below removes repeats entirely.
- **The wait is synchronous.** A large scan holds the request open with no
  progress indicator. Past a couple of minutes this wants a background job.

`maxDuration` is 300s, the Fluid Compute default and the Hobby ceiling. Pro and
Enterprise can raise it to 800s.

## Domain Cache

Scan results are cached per domain in Vercel's [Runtime Cache](https://vercel.com/docs/runtime-cache)
for 12 hours. Findings are domain-level, not person-level, so they are reusable across
uploads — and a public lead magnet sees the same popular domains constantly. Every hit
is 14 DNS queries not sent.

Runtime Cache ships with the platform, which keeps this free. Upstash Redis was
evaluated and rejected: its free tier caps at 10,000 requests per day and throws past
that, so one large scan would exhaust a day's quota.

Two properties to know:

- **Per-region and LRU-evicted.** Hit rates vary by where the function runs, and
  entries can disappear before their TTL. Neither can produce a wrong report — a miss
  just means scanning the domain, which is the no-cache behaviour.
- **Failed scans are never cached.** An error describes the attempt, not the domain.
  Caching one would pin a transient DNS blip to every report for 12 hours.

The cache key carries a version (`mxscan:v1:{domain}`). Bump `CACHE_VERSION` in
`src/lib/domain-cache.ts` whenever `DomainScanResult` gains a field, or old entries
will keep serving rows missing the new columns.

## Architecture

Scanning runs as a durable background job, not inside the HTTP request.

```
POST /api/scan          validate -> upload CSV to Blob -> start workflow -> 202 { runId }
scanWorkflow            parse -> scanChunk x N -> finalize
GET  /api/scan/status    run state for the form to poll
```

The synchronous version could not be made to scale, and not because of tuning. Total
work was bounded by one request's `maxDuration`, so a large scan was killed mid-flight
and delivered nothing — measured, with a 5,000-domain upload. Chunking inside that
request does not help either: the ceiling is the request, not the loop.

Now each chunk of 800 domains is a `"use step"` function with its own invocation and its
own duration budget, so total job size is unbounded by any single function limit. Steps
are individually retryable and their results are persisted, so a failure resumes instead
of restarting.

Two details worth keeping:

- **Chunks run sequentially, on purpose.** The bottleneck is resolver fair-use on a
  shared egress range, so parallel chunks would reach the throttle sooner rather than
  finish faster — the same reason more functions never helped the synchronous path.
- **Chunk results go to Blob, not into workflow state.** Only a pathname crosses the
  step boundary, so workflow state stays small no matter how many domains a job covers.

Uploads and intermediate chunk files are deleted in the finalize step. That deletion is
what makes the privacy claim below true, so it is best-effort but always attempted.

## Abuse Limits

Two layers, because they catch different things.

**Edge — Vercel WAF rate limit rule.** `POST /api/scan` is capped per IP before the
function runs. Vercel does not bill for requests the WAF blocks, so this caps cost as
well as abuse. It cannot see the request body, so it can only key on IP.

**Application — `src/lib/rate-limit.ts`.** Enforces the per-recipient-email cap, which
depends on a form field the edge never parses. Backed by Vercel's Runtime Cache so the
counter is shared across function instances in a region.

That app layer has real limitations, stated plainly:

- **Not atomic.** Read-modify-write means simultaneous requests can read the same
  count and both write `count + 1`, so a burst can slip a few over the cap.
- **Per region, LRU-evictable.** A distributed client gets one bucket per region, and
  entries can be evicted before the window closes.
- **Fails open.** A cache error allows the request. Locking every visitor out of a free
  tool because a cache blipped is the worse failure, and the edge rule still holds.

Set `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` and the limiter switches to
Upstash's atomic sliding window automatically — no code change. That is the upgrade
path if the approximate counters ever stop being good enough.

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

Six queries by default, or 14 with DKIM probing enabled, all issued in parallel:

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

That guessing is why DKIM is **opt-in**. Eight of the fourteen queries per domain exist
to probe it — 57% of all DNS traffic for the least conclusive column in the report — and
DNS throughput is what caps how many domains a run can cover. Leaving it off roughly
doubles the domains a single scan can reach, so `dkim_status` reads `not_checked` unless
the box is ticked. That value is deliberately distinct from `missing`: one means nothing
matched, the other means nothing was asked.

Cache keys include the mode (`mxscan:v1:base:` vs `mxscan:v1:dkim:`). Without that, a
fast-mode entry would satisfy a later DKIM run and silently report no DKIM data for a
check the user explicitly requested.

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
