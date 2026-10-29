import { describe, expect, it } from "vitest";

import type { Issue, Report, RspamdResult, SpamAssassinResult } from "#lib/api/types.gen.js";
import { sectionIssues, sectionStatus, sectionStatuses, spamStatus } from "#lib/sections.js";

/** An issue of the analyser, as it reports them. */
function analyserIssue(type: Issue["type"], fields: Partial<Issue> = {}): Issue {
    return {
        type,
        category: "deliverability",
        severity: "medium",
        message: `${type} found`,
        location: "example.com",
        penalty: 0,
        ...fields,
    };
}

/** A report where every check passes, to be spoiled one field at a time by each test. */
function report(fields: Partial<Report> = {}): Report {
    return {
        id: "r",
        test_id: "t",
        score: 100,
        grade: "A+",
        created_at: "2026-01-01T00:00:00Z",
        source: "received",
        summary: {
            dns_score: 100,
            dns_grade: "A+",
            authentication_score: 100,
            authentication_grade: "A+",
            spam_score: 100,
            spam_grade: "A+",
            blacklist_score: 100,
            blacklist_grade: "A+",
            header_score: 100,
            header_grade: "A+",
            content_score: 100,
            content_grade: "A+",
            attachments_score: 0,
            attachments_grade: "" as never,
        },
        authentication: {
            spf: { result: "pass", domain: "example.com" },
            dkim: [{ result: "pass", domain: "example.com", selector: "s1" }],
            dmarc: { result: "pass", domain: "example.com" },
            bimi: { result: "pass", domain: "example.com" },
        },
        dns_results: {
            from_domain: "example.com",
            sender_ip: "192.0.2.1",
            ptr_records: ["mail.example.com."],
            ptr_forward_records: ["192.0.2.1"],
            helo_hostname: "mail.example.com",
            helo_ptr_match: true,
            spf_records: [
                {
                    domain: "example.com",
                    record: "v=spf1 ip4:192.0.2.1 -all",
                    valid: true,
                    all_qualifier: "-",
                },
            ],
            dkim_records: [
                {
                    selector: "s1",
                    domain: "example.com",
                    valid: true,
                    key_size: 2048,
                    signing_algorithm: "rsa-sha256",
                },
            ],
            dmarc_record: { record: "v=DMARC1; p=reject", policy: "reject", valid: true },
            bimi_record: {
                selector: "default",
                domain: "example.com",
                record: "v=BIMI1;",
                valid: true,
            },
        },
        blacklists: { "192.0.2.1": [{ rbl: "zen.spamhaus.org", listed: false }] },
        ...fields,
    };
}

describe("sectionIssues", () => {
    it("has nothing to say about a report where everything passes", () => {
        const r = report();
        for (const key of ["dns", "authentication", "blacklist", "headers", "content"] as const) {
            expect(sectionIssues(r, key)).toEqual([]);
        }
    });

    it("gathers what the analyser found in every check of a section", () => {
        const r = report({
            blacklist_issues: { "192.0.2.1": [analyserIssue("rbl_listed")] },
            domain_reputation: {
                verdict: "listed",
                results: [],
                issues: { sources: [analyserIssue("domain_listed")] },
            } as unknown as Report["domain_reputation"],
            content_analysis: {
                issues: { images: [analyserIssue("excessive_images")] },
                links: [
                    {
                        url: "https://example.com",
                        status: "broken",
                        issues: [analyserIssue("unreachable_link")],
                    },
                ],
            },
        });
        r.dns_results!.issues = {
            spf: [analyserIssue("spf_missing")],
            dmarc: [analyserIssue("dmarc_missing")],
        };

        expect(sectionIssues(r, "dns").map((i) => i.type)).toEqual([
            "spf_missing",
            "dmarc_missing",
        ]);
        expect(sectionIssues(r, "blacklist").map((i) => i.type)).toEqual([
            "rbl_listed",
            "domain_listed",
        ]);
        expect(sectionIssues(r, "content").map((i) => i.type)).toEqual([
            "excessive_images",
            "unreachable_link",
        ]);
    });
});

describe("sectionStatus", () => {
    it("does not claim every check passed next to a score below 100%", () => {
        expect(sectionStatus([], false, 90).label).toBe("No issue found");
        expect(sectionStatus([], false, 100).label).toBe("All checks passed");
    });

    it("opens a section only when something is to be fixed", () => {
        const suggestion = analyserIssue("domain_young", { severity: "low" });
        expect(sectionStatus([suggestion]).needsAttention).toBe(false);
        expect(sectionStatus([{ ...suggestion, severity: "high" }]).needsAttention).toBe(true);
    });

    it("counts one change for the same defect found on several links", () => {
        const dead = (url: string) =>
            analyserIssue("unreachable_link", { location: url, advice: "Fix the link" });
        expect(
            sectionStatus([
                dead("https://example.com/a"),
                dead("https://example.com/b"),
                analyserIssue("missing_alt", { advice: "Add alt text" }),
            ]).label,
        ).toBe("2 to fix");
    });
});

const sa = (fields: Partial<SpamAssassinResult>): SpamAssassinResult => ({
    score: 0,
    required_score: 5,
    is_spam: false,
    test_details: {},
    ...fields,
});

const rspamd = (fields: Partial<RspamdResult>): RspamdResult => ({
    score: 0,
    is_spam: false,
    symbols: {},
    ...fields,
});

describe("spamStatus", () => {
    it("leaves a message both filters let through to the general rule", () => {
        expect(
            spamStatus({
                spamassassin: sa({ deliverability_score: 100 }),
                rspamd: rspamd({ deliverability_score: 100 }),
            }),
        ).toBeUndefined();
    });

    it("says when one filter classifies the message as spam", () => {
        expect(
            spamStatus({
                spamassassin: sa({ deliverability_score: 100 }),
                rspamd: rspamd({ is_spam: true, deliverability_score: 0 }),
            }),
        ).toEqual({ label: "Classified as spam", tone: "danger", needsAttention: true });
    });

    it("warns of a score that cost points, gravely past half of them", () => {
        expect(spamStatus({ spamassassin: sa({ deliverability_score: 80 }) })?.tone).toBe(
            "warning",
        );
        expect(spamStatus({ rspamd: rspamd({ deliverability_score: 30 }) })?.tone).toBe("danger");
    });
});

describe("sectionStatuses", () => {
    it("reads the spam section off the verdicts of its filters", () => {
        const r = report({ rspamd: rspamd({ is_spam: true, deliverability_score: 0 }) });
        expect(sectionStatuses(r).spam?.label).toBe("Classified as spam");
        expect(
            sectionStatuses(report({ rspamd: rspamd({ deliverability_score: 100 }) })).spam?.label,
        ).toBe("All checks passed");
    });
});
