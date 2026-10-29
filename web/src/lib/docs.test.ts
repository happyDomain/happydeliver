import { describe, expect, it } from "vitest";

import { docs, headerDocLinks, issueDocLinks, rblLookupLink } from "#lib/docs.js";

describe("docs", () => {
    it("points an RFC section at its anchor", () => {
        expect(docs.spfAll).toEqual({
            label: "RFC 7208 §5.1",
            title: 'SPF "all" mechanism',
            url: "https://www.rfc-editor.org/rfc/rfc7208.html#section-5.1",
        });
        expect(docs.spf.url).toBe("https://www.rfc-editor.org/rfc/rfc7208.html");
    });
});

describe("headerDocLinks", () => {
    it("finds a field whatever its case", () => {
        expect(headerDocLinks("Message-ID")).toEqual([docs.messageId]);
    });

    it("gives no link for a field it does not know", () => {
        expect(headerDocLinks("X-Mailer")).toEqual([]);
    });
});

describe("issueDocLinks", () => {
    it("gives no link for a type left to judgement", () => {
        expect(issueDocLinks("excessive_images")).toEqual([]);
    });
});

describe("rblLookupLink", () => {
    it("names the list it was asked about, whatever its case", () => {
        expect(rblLookupLink("ZEN.Spamhaus.org")).toEqual({
            label: "Spamhaus",
            url: "https://check.spamhaus.org/",
            title: "Look up and request removal from ZEN.Spamhaus.org",
        });
    });

    it("leaves a list it does not know without a link", () => {
        expect(rblLookupLink("bl.example.org")).toBeUndefined();
    });
});
