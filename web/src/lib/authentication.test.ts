import { describe, expect, it } from "vitest";

import {
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
