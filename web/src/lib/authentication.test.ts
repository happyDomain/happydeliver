import { describe, expect, it } from "vitest";

import type { AuthenticationResults, DomainAlignment } from "#lib/api/types.gen.js";
import {
    alignmentIdentities,
    isAlignedWith,
    parseVerdictDetails,
    rawVerdict,
    sameDomain,
    verdictMeaning,
    verdictStatus,
} from "#lib/authentication.js";

describe("parseVerdictDetails", () => {
    it("keeps the properties and the comments, not the result", () => {
        expect(
            parseVerdictDetails(
                "pass (google.com: domain of a@example.com designates 192.0.2.1 as permitted sender) smtp.mailfrom=a@example.com",
            ),
        ).toEqual({
            comments: [
                "google.com: domain of a@example.com designates 192.0.2.1 as permitted sender",
            ],
            properties: { "smtp.mailfrom": "a@example.com" },
        });
    });

    it("unquotes values and reads nested comments whole", () => {
        const parsed = parseVerdictDetails(
            'fail (p=REJECT (applied)) header.from=example.com reason="no key"; policy.dmarc=reject',
        );
        expect(parsed.comments).toEqual(["p=REJECT (applied)"]);
        expect(parsed.properties).toEqual({
            "header.from": "example.com",
            reason: "no key",
            "policy.dmarc": "reject",
        });
    });

    it("lowercases the names of the properties", () => {
        expect(parseVerdictDetails("pass Header.D=example.com").properties).toEqual({
            "header.d": "example.com",
        });
    });

    it("keeps an escaped parenthesis in a comment", () => {
        expect(parseVerdictDetails("pass (a \\) b) header.d=example.com")).toEqual({
            comments: ["a ) b"],
            properties: { "header.d": "example.com" },
        });
    });

    it("reads a comment left open to the end", () => {
        expect(parseVerdictDetails("pass smtp.mailfrom=a@example.com (truncated")).toEqual({
            comments: ["truncated"],
            properties: { "smtp.mailfrom": "a@example.com" },
        });
    });

    it("reads nothing out of nothing", () => {
        expect(parseVerdictDetails(undefined)).toEqual({ comments: [], properties: {} });
    });
});

describe("rawVerdict", () => {
    it("puts the method back in front of what the receiver wrote", () => {
        expect(rawVerdict("spf", "pass", "pass smtp.mailfrom=a@example.com")).toBe(
            "spf=pass smtp.mailfrom=a@example.com",
        );
        expect(rawVerdict("dmarc", "fail", "fail(p=none)")).toBe("dmarc=fail(p=none)");
    });

    it("leaves a legacy Received-SPF header as it is", () => {
        expect(rawVerdict("spf", "pass", "Pass (mailfrom) identity=mailfrom")).toBe(
            "Pass (mailfrom) identity=mailfrom",
        );
        expect(rawVerdict("spf", "softfail", "example.com: 192.0.2.1 is not allowed")).toBe(
            "example.com: 192.0.2.1 is not allowed",
        );
    });

    it("has nothing to show without details", () => {
        expect(rawVerdict("spf", "pass", undefined)).toBeUndefined();
    });
});

describe("sameDomain", () => {
    it("ignores the case and a trailing dot", () => {
        expect(sameDomain("Example.COM.", "example.com")).toBe(true);
        expect(sameDomain("mail.example.com", "example.com")).toBe(false);
    });

    it("never matches a missing domain", () => {
        expect(sameDomain(undefined, undefined)).toBe(false);
        expect(sameDomain("", "")).toBe(false);
    });
});

describe("isAlignedWith", () => {
    it("aligns the From domain with itself, whatever the mode", () => {
        expect(isAlignedWith("Example.com.", undefined, "example.com", undefined, "strict")).toBe(
            true,
        );
    });

    it("compares organizational domains in relaxed mode only", () => {
        expect(isAlignedWith("mail.example.com", "example.com", "example.com", "example.com")).toBe(
            true,
        );
        expect(
            isAlignedWith(
                "mail.example.com",
                "example.com",
                "example.com",
                "example.com",
                "strict",
            ),
        ).toBe(false);
        expect(isAlignedWith("example.net", "example.net", "example.com", "example.com")).toBe(
            false,
        );
    });

    it("cannot tell without the organizational domains", () => {
        expect(isAlignedWith("mail.example.com", undefined, "example.com", undefined)).toBe(
            undefined,
        );
        expect(isAlignedWith(undefined, undefined, "example.com", "example.com")).toBe(undefined);
    });
});

describe("verdictMeaning", () => {
    it("explains a verdict in the terms of its mechanism", () => {
        expect(verdictMeaning("spf", "softfail")).toMatch(/~all/);
        expect(verdictMeaning("spf_helo", "pass")).toMatch(/announced hostname/);
        expect(verdictMeaning("spf_helo", "softfail")).toBe(verdictMeaning("spf", "softfail"));
    });

    it("says nothing of a verdict it does not know", () => {
        expect(verdictMeaning("dkim", "policy")).toBeUndefined();
        expect(verdictMeaning("dkim", undefined)).toBeUndefined();
    });
});

describe("verdictStatus", () => {
    it("reads a missing verdict as a failure only when it is required", () => {
        expect(verdictStatus("none", true)).toBe("fail");
        expect(verdictStatus("none", false)).toBe("neutral");
        expect(verdictStatus(undefined, true)).toBe("fail");
    });

    it("reads the verdicts in between as warnings", () => {
        expect(verdictStatus("softfail", true)).toBe("warn");
        expect(verdictStatus("orgdomain_pass", true)).toBe("pass");
        expect(verdictStatus("skipped", true)).toBe("info");
    });
});

describe("alignmentIdentities", () => {
    const alignment: DomainAlignment = {
        from_domain: "example.com",
        from_org_domain: "example.com",
        return_path: "bounce@mail.example.com",
        return_path_domain: "mail.example.com",
        return_path_org_domain: "example.com",
        dkim_domains: [
            { domain: "example.net", org_domain: "example.net" },
            { domain: "example.com", org_domain: "example.com" },
        ],
    };
    const authentication: AuthenticationResults = {
        spf: { result: "pass", domain: "mail.example.com" },
        dkim: [
            { result: "pass", domain: "example.net", selector: "s1" },
            { result: "fail", domain: "example.com", selector: "s2" },
        ],
    };

    it("holds each identity against the From domain, with its own verdict", () => {
        const [spf, net, com] = alignmentIdentities(alignment, authentication, undefined);
        expect(spf).toMatchObject({
            mechanism: "SPF",
            address: "bounce@mail.example.com",
            relation: "organizational",
            aligned: true,
            counts: true,
        });
        expect(net).toMatchObject({
            relation: "unrelated",
            aligned: false,
            counts: false,
            selector: "s1",
        });
        expect(com).toMatchObject({ relation: "same", aligned: true, counts: false });
        expect(com.verdict?.selector).toBe("s2");
    });

    it("asks for the From domain itself under strict alignment", () => {
        const [spf] = alignmentIdentities(alignment, authentication, {
            valid: true,
            spf_alignment: "strict",
        });
        expect(spf).toMatchObject({ relation: "organizational", aligned: false, counts: false });
    });

    it("leaves out the SPF verdict of another envelope sender", () => {
        const [spf] = alignmentIdentities(
            alignment,
            { spf: { result: "pass", domain: "example.org" } },
            undefined,
        );
        expect(spf.verdict).toBeUndefined();
        expect(spf.counts).toBe(false);
    });

    it("takes an SPF verdict naming no domain as the Return-Path's", () => {
        const [spf] = alignmentIdentities(alignment, { spf: { result: "pass" } }, undefined);
        expect(spf).toMatchObject({ verdict: { result: "pass" }, counts: true });
    });

    it("matches the signatures in order, skipping those without a domain", () => {
        const [, net, com] = alignmentIdentities(
            alignment,
            { dkim: [{ result: "none" }, ...authentication.dkim!] },
            undefined,
        );
        expect(net.verdict?.selector).toBe("s1");
        expect(com.verdict?.selector).toBe("s2");
    });

    it("matches the signatures by domain when the lists differ", () => {
        const [, net] = alignmentIdentities(
            alignment,
            { dkim: [{ result: "pass", domain: "example.net", selector: "s1" }] },
            undefined,
        );
        expect(net.verdict?.selector).toBe("s1");
    });

    it("has nothing to compare without an alignment", () => {
        expect(alignmentIdentities(undefined, authentication, undefined)).toEqual([]);
    });
});
