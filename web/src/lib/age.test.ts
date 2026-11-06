import { describe, expect, it } from "vitest";

import type { Report } from "#lib/api/types.gen.js";
import { ageLevel, analysisLag, formatDuration } from "./age.js";

const HOUR = 3600 * 1000;

function report(createdAt: string, ...received: (string | undefined)[]): Report {
    return {
        created_at: createdAt,
        header_analysis: { received_chain: received.map((timestamp) => ({ timestamp })) },
    } as Report;
}

describe("ageLevel", () => {
    it("stays quiet up to six hours, and warns past a day", () => {
        expect(ageLevel(6 * HOUR)).toBeNull();
        expect(ageLevel(7 * HOUR)).toBe("info");
        expect(ageLevel(25 * HOUR)).toBe("warning");
    });
});

describe("analysisLag", () => {
    it("measures from the newest hop", () => {
        const lag = analysisLag(
            report("2026-11-01T12:00:00Z", "2026-11-01T09:00:00Z", "2026-11-01T01:00:00Z"),
        );
        expect(lag).toBe(3 * HOUR);
    });

    it("has nothing to say without a date", () => {
        expect(analysisLag(report("2026-11-01T12:00:00Z"))).toBeNull();
        expect(analysisLag(report("2026-11-01T12:00:00Z", undefined))).toBeNull();
        expect(analysisLag(report("2026-11-01T12:00:00Z", "not a date"))).toBeNull();
    });

    it("ignores a reception dated after the report", () => {
        expect(analysisLag(report("2026-11-01T12:00:00Z", "2026-11-01T13:00:00Z"))).toBeNull();
    });
});

describe("formatDuration", () => {
    it("reads as part of a sentence", () => {
        expect(formatDuration(HOUR)).toBe("1 hour");
        expect(formatDuration(7 * HOUR)).toBe("7 hours");
        expect(formatDuration(24 * HOUR)).toBe("1 day");
        expect(formatDuration(72 * HOUR)).toBe("3 days");
    });
});
