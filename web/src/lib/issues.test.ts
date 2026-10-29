import { describe, expect, it } from "vitest";

import type { ContentAnalysis, Issue } from "#lib/api/types.gen.js";
import {
    adviceAnchorsBySymbol,
    categoryLabel,
    contentAnchor,
    contentIssues,
    groupByChange,
    groupIssuesByCategory,
    isActionable,
    issueLabel,
    issueObserver,
    listed,
} from "#lib/issues.js";

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
    it("points a symbol at the check showing the finding it raised", () => {
        const anchors = adviceAnchorsBySymbol({
            issues: {
                images: [issue({ type: "missing_alt" })],
                markup: [issue({ type: "hidden_text", source: "rspamd", symbol: "ZERO_FONT" })],
            },
        });

        expect(anchors).toEqual({ ZERO_FONT: contentAnchor("markup") });
    });

    it("points a symbol at our finding when it only corroborated it", () => {
        const anchors = adviceAnchorsBySymbol({
            issues: {
                images: [
                    issue({ type: "excessive_images", corroborated_by: ["R_SUSPICIOUS_IMAGES"] }),
                ],
            },
        });

        expect(anchors).toEqual({ R_SUSPICIOUS_IMAGES: contentAnchor("images") });
    });

    it("points a symbol about one link at the links", () => {
        const anchors = adviceAnchorsBySymbol({
            links: [
                {
                    url: "https://example.com",
                    status: "suspicious",
                    issues: [
                        issue({ corroborated_by: ["REDIRECTOR_URL", "URL_REDIRECTOR_NESTED"] }),
                    ],
                },
            ],
        });

        expect(anchors).toEqual({
            REDIRECTOR_URL: contentAnchor("links"),
            URL_REDIRECTOR_NESTED: contentAnchor("links"),
        });
    });

    it("points a symbol about one image at the images", () => {
        const anchors = adviceAnchorsBySymbol({
            images: [{ has_alt: true, issues: [issue({ symbol: "R_SUSPICIOUS_IMAGES" })] }],
        });

        expect(anchors).toEqual({ R_SUSPICIOUS_IMAGES: contentAnchor("images") });
    });

    it("names the anchor of a check after it, dashes for underscores", () => {
        expect(contentAnchor("text_alternative")).toBe("content-text-alternative");
    });

    it("points a symbol of a report from before the checks at the section", () => {
        const anchors = adviceAnchorsBySymbol({
            html_issues: [issue({ type: "hidden_text", symbol: "ZERO_FONT" })],
        });

        expect(anchors).toEqual({ ZERO_FONT: "content-details" });
    });

    it("survives a report with no content issues at all", () => {
        expect(adviceAnchorsBySymbol(undefined)).toEqual({});
        expect(adviceAnchorsBySymbol({})).toEqual({});
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
        expect(issueLabel("double_extension")).toBe("Deceptive double extension");
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
        expect(issueObserver({ source: "virustotal" })).toBe("virustotal");
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

describe("groupByChange", () => {
    it("takes the same defect with the same advice as one change", () => {
        const groups = groupByChange([
            issue({ type: "unreachable_link", advice: "Fix it", location: "a" }),
            issue({ type: "missing_alt", advice: "Describe it", location: "img" }),
            issue({ type: "unreachable_link", advice: "Fix it", location: "b" }),
            issue({ type: "unreachable_link", advice: "Other", location: "c" }),
        ]);

        expect(groups.map((g) => g.map((i) => i.location))).toEqual([["a", "b"], ["img"], ["c"]]);
    });
});

describe("contentIssues", () => {
    it("reads the checks, then the links and the images, and a report from before them", () => {
        const all = contentIssues({
            html_issues: [issue({ location: "legacy" })],
            issues: { structure: [issue({ location: "structure" })] },
            links: [
                {
                    url: "https://example.com",
                    status: "valid",
                    issues: [issue({ location: "link" })],
                },
            ],
            images: [{ has_alt: true, issues: [issue({ location: "image" })] }],
        } as ContentAnalysis);

        expect(all.map((i) => i.location)).toEqual(["legacy", "structure", "link", "image"]);
    });
});

describe("isActionable", () => {
    it("calls for a change from medium up, and only suggests one below", () => {
        const actionable = (["critical", "high", "medium", "low", "info"] as const).filter(
            (severity) => isActionable({ severity }),
        );
        expect(actionable).toEqual(["critical", "high", "medium"]);
    });
});

describe("listed", () => {
    it("gives nothing for a check without issues", () => {
        expect(listed([])).toBeUndefined();
        expect(listed(undefined)).toBeUndefined();
        expect(listed([issue({})])).toHaveLength(1);
    });
});
