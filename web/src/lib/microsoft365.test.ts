import { describe, expect, it } from "vitest";

import { m365BclMeaning, m365UnderPresets } from "./microsoft365.js";

describe("m365BclMeaning", () => {
    it("places a level against the thresholds of each policy", () => {
        expect(m365BclMeaning(0)).toBe("not from a bulk sender");
        expect(m365BclMeaning(4)).toBe("from a bulk sender, below the thresholds");
        expect(m365BclMeaning(5)).toBe("bulk under the Strict preset policy");
        expect(m365BclMeaning(6)).toBe("bulk under the Standard and Strict preset policies");
        expect(m365BclMeaning(7)).toBe("bulk under every policy");
    });
});

describe("m365UnderPresets", () => {
    it("says nothing of a clean message", () => {
        expect(m365UnderPresets({ category: "NONE", filter_verdict: "NSPM", bcl: 0 })).toBe(
            undefined,
        );
    });

    it("says nothing of a message leaving its tenant", () => {
        expect(m365UnderPresets({ direction: "outbound", category: "SPM" })).toBe(undefined);
    });

    it("tells high confidence spam is quarantined by both preset policies", () => {
        expect(m365UnderPresets({ category: "HSPM" })).toBe(
            "quarantined under the Standard and Strict preset policies",
        );
    });

    it("tells bulk below the default threshold is acted on by the preset policies", () => {
        expect(m365UnderPresets({ category: "NONE", bcl: 6 })).toBe(
            "junk folder under the Standard preset policy, quarantined under the Strict one",
        );
        expect(m365UnderPresets({ category: "NONE", bcl: 5 })).toBe(
            "quarantined under the Strict preset policy",
        );
    });

    it("counts a spam verdict without a category", () => {
        expect(m365UnderPresets({ filter_verdict: "SKS" })).toBe(
            "quarantined under the Strict preset policy",
        );
    });
});
