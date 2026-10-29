import { describe, expect, it } from "vitest";

import { verdictStatus } from "#lib/authentication.js";

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
