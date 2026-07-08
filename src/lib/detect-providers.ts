import { providerRules } from "./provider-rules";
import type { EmailSecurityClassification, ProviderCategory, ProviderDetection, ProviderRule } from "./types";

function includesPattern(value: string, pattern: string) {
  return value.toLowerCase().includes(pattern.toLowerCase());
}

function toDetection(rule: ProviderRule, category: ProviderCategory, recordType: "MX" | "TXT" | "SPF", record: string, pattern: string): ProviderDetection {
  return {
    providerId: rule.id,
    providerName: rule.name,
    category,
    confidence: rule.confidence,
    evidence: [
      {
        recordType,
        record,
        reason: `${recordType} record matched ${pattern}`,
      },
    ],
  };
}

function mergeDetection(existing: ProviderDetection | undefined, next: ProviderDetection) {
  if (!existing) return next;
  return { ...existing, evidence: [...existing.evidence, ...next.evidence] };
}

function highestConfidence(detections: ProviderDetection[]) {
  const rank = { high: 3, medium: 2, low: 1, unknown: 0 };
  return detections.sort((a, b) => rank[b.confidence] - rank[a.confidence])[0] ?? null;
}

export function detectProviders(mxRecords: string[], txtRecords: string[]): EmailSecurityClassification {
  const byKey = new Map<string, ProviderDetection>();

  for (const rule of providerRules) {
    for (const record of mxRecords) {
      for (const pattern of rule.mxPatterns ?? []) {
        if (!includesPattern(record, pattern)) continue;

        const category = rule.categories.includes("seg") ? "seg" : rule.categories[0];
        const next = toDetection(rule, category, "MX", record, pattern);
        const key = `${rule.id}:${category}`;
        byKey.set(key, mergeDetection(byKey.get(key), next));
      }
    }

    for (const record of txtRecords) {
      for (const pattern of rule.txtPatterns ?? []) {
        if (!includesPattern(record, pattern)) continue;

        const category = rule.categories.includes("seg") ? "seg" : rule.categories[0];
        const next = toDetection(rule, category, "TXT", record, pattern);
        const key = `${rule.id}:${category}`;
        byKey.set(key, mergeDetection(byKey.get(key), next));
      }

      if (!record.toLowerCase().startsWith("v=spf1")) continue;

      for (const pattern of rule.spfIncludePatterns ?? []) {
        if (!includesPattern(record, pattern)) continue;

        const category = rule.categories.includes("outbound_sender") ? "outbound_sender" : rule.categories[0];
        const next = toDetection(rule, category, "SPF", record, pattern);
        const key = `${rule.id}:${category}`;
        byKey.set(key, mergeDetection(byKey.get(key), next));
      }
    }
  }

  const detections = [...byKey.values()];
  const segDetections = detections.filter((d) => d.category === "seg");
  const mailboxDetections = detections.filter((d) => d.category === "mailbox");

  return {
    inboundProvider: highestConfidence([...segDetections, ...mailboxDetections]),
    mailboxProvider: highestConfidence(mailboxDetections),
    outboundSenders: detections.filter((d) => d.category === "outbound_sender"),
    securityGateway: highestConfidence(segDetections),
  };
}
