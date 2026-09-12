import { describe, expect, it } from "vitest";

import type { ContentIssue } from "$lib/api/types.gen";
import { adviceAnchorsBySymbol, contentIssueAnchor, contentIssueLabel } from "$lib/issues";

/** A content issue with only the fields these tests care about. */
function issue(fields: Partial<ContentIssue>): ContentIssue {
    return {
        type: "suspicious_link",
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

describe("contentIssueLabel", () => {
    it("names a type rather than printing the enum", () => {
        expect(contentIssueLabel("missing_alt")).toBe("Missing alt text");
        expect(contentIssueLabel("homograph_url")).toBe("Look-alike URL");
    });

    it("still reads as something for a type the API added and we have not", () => {
        // Not reachable through the type, but reachable from an older front end
        // talking to a newer server.
        expect(contentIssueLabel("some_new_kind" as ContentIssue["type"])).toBe("some new kind");
    });
});
