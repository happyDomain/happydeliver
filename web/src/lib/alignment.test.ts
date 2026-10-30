import { describe, expect, it } from "vitest";

import type { DmarcRecord, DomainAlignment } from "#lib/api/types.gen.js";
import { dmarcAlignment } from "#lib/alignment.js";

const strict: DmarcRecord = { valid: true, spf_alignment: "strict", dkim_alignment: "strict" };
const strictDkim: DmarcRecord = { valid: true, dkim_alignment: "strict" };

/** The alignment of a message from example.com, with the given Return-Path and DKIM domains. */
function alignment(rp: string, ...dkim: [string, string][]): DomainAlignment {
    return {
        from_domain: "example.com",
        from_org_domain: "example.com",
        return_path_domain: rp || undefined,
        return_path_org_domain: rp ? rp.split(".").slice(-2).join(".") : undefined,
        dkim_domains: dkim.map(([domain, org_domain]) => ({ domain, org_domain })),
        aligned: false,
        relaxed_aligned: false,
    };
}

describe("dmarcAlignment", () => {
    it("counts the From domain itself whatever the mode", () => {
        expect(dmarcAlignment(alignment("example.com"), strict)).toBe("exact");
    });

    it("counts a subdomain in relaxed mode, the default", () => {
        expect(dmarcAlignment(alignment("", ["mail.example.com", "example.com"]), undefined)).toBe(
            "organizational",
        );
    });

    it("does not count a subdomain under a strict mode", () => {
        expect(dmarcAlignment(alignment("", ["mail.example.com", "example.com"]), strictDkim)).toBe(
            "none",
        );
    });

    it("applies each mode to its own identity", () => {
        expect(
            dmarcAlignment(
                alignment("bounce.example.com", ["mail.example.com", "example.com"]),
                strictDkim,
            ),
        ).toBe("organizational");
    });

    it("ignores the modes of an invalid record", () => {
        expect(
            dmarcAlignment(alignment("", ["mail.example.com", "example.com"]), {
                ...strict,
                valid: false,
            }),
        ).toBe("organizational");
    });

    it("keeps the analysis verdict when there is nothing to compare", () => {
        expect(
            dmarcAlignment(
                { from_domain: "example.com", aligned: true, relaxed_aligned: true },
                strict,
            ),
        ).toBe("exact");
    });
});
