import { describe, expect, it } from "vitest";

import type { Issue } from "$lib/api/types.gen";
import {
    adviceAnchorsBySymbol,
    categoryLabel,
    contentIssueAnchor,
    groupIssuesByCategory,
    issueLabel,
    issueObserver,
} from "$lib/issues";

/** A content issue with only the fields these tests care about. */
function issue(fields: Partial<Issue>): Issue {
    return {
        type: "suspicious_link",
        category: "security",
        severity: "medium",
        message: "something",
        ...fields,
    };
}

describe("adviceAnchorsBySymbol", () => {
    it("points a symbol at the finding it raised", () => {
        const anchors = adviceAnchorsBySymbol([
            issue({ type: "missing_alt" }),
            issue({ type: "hidden_text", source: "rspamd", symbol: "ZERO_FONT" }),
        ]);

        expect(anchors).toEqual({ ZERO_FONT: contentIssueAnchor(1) });
    });

    it("points a symbol at our finding when it only corroborated it", () => {
        const anchors = adviceAnchorsBySymbol([
            issue({ type: "excessive_images", corroborated_by: ["R_SUSPICIOUS_IMAGES"] }),
        ]);

        expect(anchors).toEqual({ R_SUSPICIOUS_IMAGES: contentIssueAnchor(0) });
    });

    it("points every corroborator of one finding at that finding", () => {
        const anchors = adviceAnchorsBySymbol([
            issue({ corroborated_by: ["REDIRECTOR_URL", "URL_REDIRECTOR_NESTED"] }),
        ]);

        expect(anchors).toEqual({
            REDIRECTOR_URL: contentIssueAnchor(0),
            URL_REDIRECTOR_NESTED: contentIssueAnchor(0),
        });
    });

    it("leaves a symbol that produced no finding without an anchor", () => {
        const anchors = adviceAnchorsBySymbol([issue({ type: "missing_alt" })]);

        expect(anchors["ARC_NA"]).toBeUndefined();
    });

    it("survives a report with no content issues at all", () => {
        expect(adviceAnchorsBySymbol(undefined)).toEqual({});
        expect(adviceAnchorsBySymbol([])).toEqual({});
    });
});

describe("issueLabel", () => {
    it("names a type rather than printing the enum", () => {
        expect(issueLabel("missing_alt")).toBe("Missing alt text");
        expect(issueLabel("homograph_url")).toBe("Look-alike URL");
    });

    it("names what a message carries as well as what it says", () => {
        // One vocabulary, two readings: an attachment finding is labelled by
        // the same table as a body one.
        expect(issueLabel("malware_detected")).toBe("Malware detected");
        expect(issueLabel("scan_skipped")).toBe("Not fully scanned");
    });

    it("still reads as something for a type the API added and we have not", () => {
        // Not reachable through the type, but reachable from an older front end
        // talking to a newer server.
        expect(issueLabel("some_new_kind" as Issue["type"])).toBe("some new kind");
    });
});

describe("categoryLabel", () => {
    it("names a reading rather than printing the enum", () => {
        expect(categoryLabel("deliverability")).toBe("Deliverability");
    });

    it("still reads as something for a reading the API added and we have not", () => {
        expect(categoryLabel("some_new_reading" as Issue["category"])).toBe("some new reading");
    });
});

describe("issueObserver", () => {
    it("says nothing about what happyDeliver read for itself", () => {
        expect(issueObserver({ source: undefined })).toBeUndefined();
        expect(issueObserver({ source: "self" })).toBeUndefined();
    });

    it("names whoever else observed it", () => {
        expect(issueObserver({ source: "rspamd" })).toBe("rspamd");
        expect(issueObserver({ source: "clamav" })).toBe("clamav");
    });
});

describe("groupIssuesByCategory", () => {
    it("shows the groups in the order they are meant to be read", () => {
        const groups = groupIssuesByCategory([
            issue({ category: "accessibility" }),
            issue({ category: "security" }),
            issue({ category: "content" }),
        ]);

        expect(groups.map((group) => group.category)).toEqual([
            "security",
            "content",
            "accessibility",
        ]);
    });

    it("keeps every issue at the index its anchor is made of", () => {
        const issues = [
            issue({ category: "accessibility", message: "pale" }),
            issue({ category: "security", message: "look-alike" }),
            issue({ category: "accessibility", message: "no alt" }),
        ];

        const groups = groupIssuesByCategory(issues);

        // The security group comes first, but its issue is still the second of html_issues,
        // which is what the rspamd symbol table links to.
        expect(groups[0].issues).toEqual([{ issue: issues[1], index: 1 }]);
        expect(groups[1].issues).toEqual([
            { issue: issues[0], index: 0 },
            { issue: issues[2], index: 2 },
        ]);
    });

    it("leaves the issues the severity does not separate in the order the analysis reported them", () => {
        const issues = [
            issue({ category: "rendering", message: "first" }),
            issue({ category: "rendering", message: "second" }),
        ];

        expect(
            groupIssuesByCategory(issues)[0].issues.map((placed) => placed.issue.message),
        ).toEqual(["first", "second"]);
    });

    it("opens a group on its gravest finding", () => {
        const issues = [
            issue({ category: "rendering", severity: "info", message: "a remark" }),
            issue({ category: "rendering", severity: "critical", message: "a real problem" }),
            issue({ category: "rendering", severity: "medium", message: "something between" }),
            issue({ category: "rendering", severity: "high", message: "nearly as bad" }),
            issue({ category: "rendering", severity: "low", message: "a detail" }),
        ];

        expect(
            groupIssuesByCategory(issues)[0].issues.map((placed) => placed.issue.severity),
        ).toEqual(["critical", "high", "medium", "low", "info"]);
    });

    it("keeps the anchors pointing at the right advice once the findings are reordered", () => {
        const issues = [
            issue({ category: "rendering", severity: "low", message: "a detail" }),
            issue({ category: "rendering", severity: "critical", message: "a real problem" }),
        ];

        const placed = groupIssuesByCategory(issues)[0].issues;

        expect(placed[0]).toEqual({ issue: issues[1], index: 1 });
        expect(placed[1]).toEqual({ issue: issues[0], index: 0 });
    });

    it("sorts a severity it does not know last rather than first", () => {
        const issues = [
            issue({
                category: "rendering",
                severity: "some_new_level" as unknown as Issue["severity"],
            }),
            issue({ category: "rendering", severity: "info" }),
        ];

        expect(
            groupIssuesByCategory(issues)[0].issues.map((placed) => placed.issue.severity),
        ).toEqual(["info", "some_new_level"]);
    });

    it("does not reorder the caller's array", () => {
        const issues = [
            issue({ category: "rendering", severity: "low" }),
            issue({ category: "rendering", severity: "critical" }),
        ];

        groupIssuesByCategory(issues);

        expect(issues.map((entry) => entry.severity)).toEqual(["low", "critical"]);
    });

    it("shows a reading we do not know rather than dropping it", () => {
        const groups = groupIssuesByCategory([
            issue({ category: "some_new_reading" as Issue["category"] }),
            issue({ category: "content" }),
        ]);

        expect(groups.map((group) => group.category)).toEqual(["content", "some_new_reading"]);
    });

    it("survives a report with no content issues at all", () => {
        expect(groupIssuesByCategory(undefined)).toEqual([]);
        expect(groupIssuesByCategory([])).toEqual([]);
    });

    // A stored report is served back exactly as it was written, so one produced before the
    // analysis recorded a reading reaches the browser with no category at all. It has to
    // read as it always did rather than throw on the way to a heading.
    it("shows a report written before categories existed as one unheaded run", () => {
        const issues = [
            issue({ category: undefined as unknown as Issue["category"] }),
            issue({ category: undefined as unknown as Issue["category"] }),
        ];

        const groups = groupIssuesByCategory(issues);

        expect(groups).toHaveLength(1);
        expect(groups[0].category).toBeUndefined();
        expect(groups[0].issues).toEqual([
            { issue: issues[0], index: 0 },
            { issue: issues[1], index: 1 },
        ]);
    });

    it("keeps an issue that carries an empty category out of the headed groups", () => {
        const groups = groupIssuesByCategory([
            issue({ category: "" as unknown as Issue["category"] }),
        ]);

        expect(groups[0].category).toBeUndefined();
    });

    // Taken from a report the stored database actually holds, addresses aside: a stored
    // report is served back byte for byte, so this is the exact shape the browser receives
    // for one written before the analysis recorded a reading.
    it("groups a report as it is really stored, with no category on any issue", () => {
        const stored = [
            {
                type: "missing_alt",
                severity: "medium",
                message: "1 image(s) missing alt attributes",
                advice: "Add descriptive alt text to all images for better accessibility and deliverability",
            },
            {
                type: "suspicious_link",
                severity: "high",
                message: "Suspicious URL detected",
                location: "mailto:someone@example.com",
                advice: "Avoid URL shorteners, IP addresses, and obfuscated URLs in emails",
            },
        ] as unknown as Issue[];

        const groups = groupIssuesByCategory(stored);

        expect(groups).toHaveLength(1);
        expect(groups[0].category).toBeUndefined();
        // The high one first, though it was written second, and each still carrying the
        // index its anchor is made of.
        expect(groups[0].issues.map((placed) => placed.index)).toEqual([1, 0]);
    });

    // A report half migrated does not exist today, but a reader of one must still find the
    // findings that do name their reading under their heading.
    it("shows the uncategorised findings after the ones that name a reading", () => {
        const groups = groupIssuesByCategory([
            issue({ category: undefined as unknown as Issue["category"] }),
            issue({ category: "security" }),
        ]);

        expect(groups.map((group) => group.category)).toEqual(["security", undefined]);
    });
});
