import { describe, expect, it } from "vitest";
import { getPrimaryMxHost } from "./dns-google";

describe("getPrimaryMxHost", () => {
  it("picks the lowest-preference host and strips the trailing dot", () => {
    expect(
      getPrimaryMxHost(["20 mxb-001.pphosted.com.", "10 mxa-001.pphosted.com.", "30 backup.example.net."]),
    ).toBe("mxa-001.pphosted.com");
  });

  it("sorts numerically, not lexically", () => {
    expect(getPrimaryMxHost(["100 high.example.com.", "9 low.example.com."])).toBe("low.example.com");
  });

  it("returns undefined for empty or malformed answers", () => {
    expect(getPrimaryMxHost([])).toBeUndefined();
    expect(getPrimaryMxHost(["not an mx record"])).toBeUndefined();
  });
});
