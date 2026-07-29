export type Confidence = "high" | "medium" | "low" | "unknown";

export type ProviderCategory = "seg" | "mailbox" | "outbound_sender" | "hosting";

export type ProviderRule = {
  id: string;
  name: string;
  categories: ProviderCategory[];
  mxPatterns?: string[];
  txtPatterns?: string[];
  spfIncludePatterns?: string[];
  confidence: Exclude<Confidence, "unknown">;
};

export type ProviderDetection = {
  providerId: string;
  providerName: string;
  category: ProviderCategory;
  confidence: Confidence;
  evidence: Array<{
    recordType: "MX" | "TXT" | "SPF" | "DMARC";
    record: string;
    reason: string;
  }>;
};

export type EmailSecurityClassification = {
  inboundProvider: ProviderDetection | null;
  mailboxProvider: ProviderDetection | null;
  outboundSenders: ProviderDetection[];
  securityGateway: ProviderDetection | null;
};

export type PolicyStatus = "present" | "missing" | "error";

export type DomainScanResult = {
  domain: string;
  mx: {
    status: "present" | "missing" | "error";
    records: string[];
    primaryHost?: string;
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
  mtaSts: {
    status: PolicyStatus;
    id?: string;
  };
  tlsRpt: {
    status: PolicyStatus;
    record?: string;
  };
  bimi: {
    status: PolicyStatus;
    record?: string;
  };
  dkim: {
    status: PolicyStatus;
    selectors: string[];
  };
  classification: EmailSecurityClassification;
  dnssec?: {
    ad: boolean;
  };
  notes: string[];
  error?: string;
};

export type EnrichmentSummary = {
  totalRows: number;
  totalValidEmails: number;
  totalUniqueDomains: number;
  providerCounts: Record<string, number>;
  unknownDomains: number;
  deliverability: {
    dmarcEnforced: number;
    spfMissing: number;
    dkimFound: number;
    mtaStsFound: number;
    bimiFound: number;
  };
};
