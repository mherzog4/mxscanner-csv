import { describe, expect, it } from "vitest";
import { detectProviders } from "./detect-providers";

describe("detectProviders", () => {
  it("detects Proofpoint from MX evidence with high confidence", () => {
    const result = detectProviders(["10 mxa-002a1b01.gslb.pphosted.com"], []);

    expect(result.securityGateway?.providerName).toBe("Proofpoint");
    expect(result.securityGateway?.confidence).toBe("high");
    expect(result.securityGateway?.evidence[0]?.recordType).toBe("MX");
  });

  it("detects Google Workspace as mailbox without labeling it as a SEG", () => {
    const result = detectProviders(["1 aspmx.l.google.com"], ["v=spf1 include:_spf.google.com ~all"]);

    expect(result.mailboxProvider?.providerName).toBe("Google Workspace");
    expect(result.securityGateway).toBeNull();
  });

  it("keeps SendGrid as an outbound sender and not a SEG", () => {
    const result = detectProviders([], ["v=spf1 include:sendgrid.net -all"]);

    expect(result.outboundSenders.map((sender) => sender.providerName)).toContain("SendGrid");
    expect(result.securityGateway).toBeNull();
  });

  // Real MX values. Consumer mailboxes route somewhere different from the
  // business tenants, so they need their own patterns to be detected at all.
  it.each([
    ["10 alt1.gmail-smtp-in.l.google.com.", "Gmail (consumer)"],
    ["5 outlook-com.olc.protection.outlook.com.", "Outlook.com / Hotmail"],
    ["2 hotmail-com.olc.protection.outlook.com.", "Outlook.com / Hotmail"],
    ["1 mta5.am0.yahoodns.net.", "Yahoo / AOL Mail"],
    ["10 mx-aol.mail.gm0.yahoodns.net.", "Yahoo / AOL Mail"],
    ["10 mx01.mail.icloud.com.", "iCloud Mail"],
    ["10 mail.protonmail.ch.", "Proton Mail"],
  ])("detects %s as %s", (mx, expected) => {
    const result = detectProviders([mx], []);

    expect(result.mailboxProvider?.providerName).toBe(expected);
    expect(result.securityGateway).toBeNull();
  });

  it("does not confuse consumer Gmail with Google Workspace", () => {
    expect(detectProviders(["10 alt1.gmail-smtp-in.l.google.com."], []).mailboxProvider?.providerName).toBe("Gmail (consumer)");
    expect(detectProviders(["1 aspmx.l.google.com."], []).mailboxProvider?.providerName).toBe("Google Workspace");
  });

  it("does not confuse consumer Outlook with a Microsoft 365 tenant", () => {
    const consumer = detectProviders(["5 outlook-com.olc.protection.outlook.com."], []);
    expect(consumer.mailboxProvider?.providerName).toBe("Outlook.com / Hotmail");
    expect(consumer.securityGateway).toBeNull();

    // A tenant MX is both the gateway (EOP) and the mailbox, so it counts in both.
    const tenant = detectProviders(["10 acme-com.mail.protection.outlook.com."], []);
    expect(tenant.securityGateway?.providerName).toBe("Microsoft 365 / EOP");
    expect(tenant.mailboxProvider?.providerName).toBe("Microsoft 365 / EOP");
  });

  it("does not let a Microsoft SPF include imply a mailbox or a gateway", () => {
    const result = detectProviders([], ["v=spf1 include:spf.protection.outlook.com -all"]);

    expect(result.outboundSenders.map((s) => s.providerName)).toContain("Microsoft 365 / EOP");
    expect(result.securityGateway).toBeNull();
    expect(result.mailboxProvider).toBeNull();
  });

  it("separates Mimecast SEG from Microsoft outbound evidence", () => {
    const result = detectProviders(["10 us-smtp-inbound-1.mimecast.com"], ["v=spf1 include:spf.protection.outlook.com -all"]);

    expect(result.securityGateway?.providerName).toBe("Mimecast");
    expect(result.outboundSenders.map((sender) => sender.providerName)).toContain("Microsoft 365 / EOP");
  });
});
