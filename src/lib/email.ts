import { randomUUID } from "node:crypto";
import { Resend } from "resend";
import type { EnrichmentSummary } from "./types";

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
  const from = process.env.EMAIL_FROM || "MX Scanner <onboarding@resend.dev>";
  const providerRows = Object.entries(summary.providerCounts)
    .sort(([, a], [, b]) => b - a)
    .map(([provider, count]) => `<tr><td>${escapeHtml(provider)}</td><td>${count}</td></tr>`)
    .join("");

  const html = `
    <div style="font-family: Arial, sans-serif; color: #111827; line-height: 1.5;">
      <h1>Your SEG-enriched CSV is ready</h1>
      <p>We scanned ${summary.totalUniqueDomains} unique domains from ${summary.totalValidEmails} valid emails across ${summary.totalRows} rows.</p>
      <h2>Provider breakdown</h2>
      <table cellpadding="8" cellspacing="0" style="border-collapse: collapse; border: 1px solid #e5e7eb;">
        <thead><tr><th align="left">Provider</th><th align="left">Rows</th></tr></thead>
        <tbody>${providerRows}</tbody>
      </table>
      <p>The enriched CSV is attached. Provider detection is confidence-scored from public DNS evidence and should be treated as enrichment, not a contractual source of truth.</p>
    </div>
  `;

  const { data, error } = await resend.emails.send({
    from,
    to: [to],
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

function escapeHtml(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
