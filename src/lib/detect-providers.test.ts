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

  it("separates Mimecast SEG from Microsoft outbound evidence", () => {
    const result = detectProviders(["10 us-smtp-inbound-1.mimecast.com"], ["v=spf1 include:spf.protection.outlook.com -all"]);

    expect(result.securityGateway?.providerName).toBe("Mimecast");
    expect(result.outboundSenders.map((sender) => sender.providerName)).toContain("Microsoft 365 / EOP");
  });
});
