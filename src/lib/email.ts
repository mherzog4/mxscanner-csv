import { randomUUID } from "node:crypto";
import { Resend } from "resend";
import type { EnrichmentSummary } from "./types";

// gtmreports.com is the verified sending domain in Resend. Replies route to a
// real inbox on purpose — the reply is the conversion path for this lead magnet.
const FROM = process.env.EMAIL_FROM || "MX SEG Scanner <reports@gtmreports.com>";
const REPLY_TO = process.env.EMAIL_REPLY_TO || "matt@gtmreports.com";

export async function sendReportEmail({
  to,
  csv,
  fileName,
  summary,
}: {
  to: string;
  csv: string;
  fileName: string;
  summary: EnrichmentSummary;
}) {
  if (!process.env.RESEND_API_KEY) {
    throw new Error("RESEND_API_KEY is not configured");
  }

  const resend = new Resend(process.env.RESEND_API_KEY);
  const providerRows = Object.entries(summary.providerCounts)
    .sort(([, a], [, b]) => b - a)
    .map(([provider, count]) => `<tr><td>${escapeHtml(provider)}</td><td>${count}</td></tr>`)
    .join("");

  const { dmarcEnforced, spfMissing, dkimFound, mtaStsFound, bimiFound } = summary.deliverability;
  const domains = summary.totalUniqueDomains;

  const html = `
    <div style="font-family: Arial, sans-serif; color: #111827; line-height: 1.5;">
      <h1>Your SEG-enriched CSV is ready</h1>
      <p>We scanned ${domains} unique domains from ${summary.totalValidEmails} valid emails across ${summary.totalRows} rows.</p>
      <h2>Provider breakdown</h2>
      <table cellpadding="8" cellspacing="0" style="border-collapse: collapse; border: 1px solid #e5e7eb;">
        <thead><tr><th align="left">Provider</th><th align="left">Rows</th></tr></thead>
        <tbody>${providerRows}</tbody>
      </table>
      <h2>Deliverability posture</h2>
      <ul>
        <li>${dmarcEnforced} of ${domains} domains enforce DMARC (p=quarantine or p=reject)</li>
        <li>${spfMissing} of ${domains} domains have a missing or duplicated SPF record</li>
        <li>${dkimFound} of ${domains} domains publish DKIM on a common selector</li>
        <li>${mtaStsFound} publish MTA-STS · ${bimiFound} publish BIMI</li>
      </ul>
      <p>The enriched CSV is attached. Provider detection is confidence-scored from public DNS evidence and should be treated as enrichment, not a contractual source of truth.</p>
      <p style="color:#6b7280; font-size: 13px;">Questions or a provider we misread? Just reply to this email — it goes straight to ${escapeHtml(REPLY_TO)}.</p>
    </div>
  `;

  const { data, error } = await resend.emails.send({
    from: FROM,
    to: [to],
    replyTo: REPLY_TO,
    subject: "Your prospect email security gateway report is ready",
    html,
    headers: { "X-Entity-Ref-ID": randomUUID() },
    attachments: [
      {
        filename: fileName,
        content: Buffer.from(csv, "utf8").toString("base64"),
      },
    ],
  });

  if (error) throw new Error(error.message);
  return data;
}

export async function addContact(email: string) {
  const audienceId = process.env.RESEND_AUDIENCE_ID;
  if (!process.env.RESEND_API_KEY || !audienceId) return;

  const resend = new Resend(process.env.RESEND_API_KEY);
  const { error } = await resend.contacts.create({ email, audienceId });
  if (error) {
    console.error("Failed to add contact to Resend audience:", error.message);
  }
}

function escapeHtml(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
