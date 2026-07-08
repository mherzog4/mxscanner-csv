# Contributing

Thanks for improving MX Scanner CSV. The most useful contributions are provider-rule fixes with DNS evidence.

## Local Setup

```bash
npm install
cp .env.example .env
npm run dev
```

## Checks

Run these before opening a PR:

```bash
npm run test
npm run typecheck
npm run build
```

## Adding Provider Mappings

Provider rules live in `src/lib/provider-rules.ts`.

Rules should include:

- Stable provider name.
- Correct category: `seg`, `mailbox`, `outbound_sender`, or `hosting`.
- MX patterns when the provider handles inbound mail.
- SPF/TXT patterns only when they are reliable supporting evidence.
- Conservative confidence level.

Accuracy rules:

- Prefer `unknown` over a false positive.
- MX evidence is stronger than SPF evidence for SEG detection.
- SPF senders like SendGrid, Mailgun, Mailchimp, HubSpot, and Salesforce should be classified as outbound senders, not SEGs.
- Add or update tests in `src/lib/detect-providers.test.ts` for meaningful mapping changes.

## Privacy

Do not add logging that prints raw uploaded email addresses, CSV rows, or report contents. Aggregate counts and domains are acceptable when needed for debugging.
