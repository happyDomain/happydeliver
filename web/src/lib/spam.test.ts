import { describe, expect, it } from "vitest";

import { formatRuleScore, inReportOrder } from "./spam.js";

describe("inReportOrder", () => {
    const rules = { DKIM_VALID_AU: 1, DKIM_SIGNED: 2, DKIM_VALID: 3, SPF_PASS: 4 };

    it("follows the raw report, matching whole names only", () => {
        const report = `
 * -0.1 DKIM_VALID_AU Message has a valid DKIM or DK signature from author's domain
 *  0.1 DKIM_SIGNED Message has a DKIM or DK signature, not necessarily valid
 * -0.1 DKIM_VALID Message has at least one valid DKIM or DK signature
 * -0.0 SPF_PASS SPF: sender matches SPF record`;
        expect(inReportOrder(rules, report).map(([n]) => n)).toEqual([
            "DKIM_VALID_AU",
            "DKIM_SIGNED",
            "DKIM_VALID",
            "SPF_PASS",
        ]);
    });

    it("falls back on the list of names, then on the name", () => {
        expect(inReportOrder(rules, undefined, ["SPF_PASS", "DKIM_VALID"]).map(([n]) => n)).toEqual(
            ["SPF_PASS", "DKIM_VALID", "DKIM_SIGNED", "DKIM_VALID_AU"],
        );
    });

    it("reads a name with regex metacharacters as written", () => {
        const report = " * 1.0 A_B Some rule\n * 1.0 A.B Another rule";
        expect(inReportOrder({ "A.B": 1, A_B: 2 }, report).map(([n]) => n)).toEqual(["A_B", "A.B"]);
    });
});

describe("formatRuleScore", () => {
    it("keeps the sign of weights too small to round", () => {
        expect(formatRuleScore(-0.0001)).toBe("−0.0001");
        expect(formatRuleScore(1.25, 2)).toBe("+1.25");
        expect(formatRuleScore(0)).toBe("0.0");
        expect(formatRuleScore(0.001, 2)).toBe("+0.001");
    });
});
