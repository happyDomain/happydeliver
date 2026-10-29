import type { Issue, Report } from "#lib/api/types.gen.js";
import { hasNoAuthenticationResults } from "#lib/authentication.js";
import { hasNoBlacklistResults } from "#lib/blacklist.js";
import { contentIssues, groupByChange, isActionable } from "#lib/issues.js";
import { hasNoSpamResults } from "#lib/spam.js";

/**
 * The sections of a report, and what each says before it is opened.
 *
 * What is wrong, where and what it costs is the analyser's to say, as the issues of each
 * check; the report only reads them. Each section is made of the checks of one analysis, and
 * shows them by the keys the API lists them under.
 */

export type SectionKey =
    "dns" | "authentication" | "blacklist" | "headers" | "spam" | "content" | "attachments";

export interface SectionSummary {
    key: SectionKey;
    label: string;
    anchor: string;
    grade?: string;
    score?: number;
    /** No result could be produced: the grade is not the sender's to improve. */
    unavailable: boolean;
}

/**
 * The sections in the order the report shows them, with the anchor the score strip links to.
 * Anchors are part of the page's public surface (links get shared), so they do not change
 * with the layout.
 */
export function sectionSummaries(report: Report): SectionSummary[] {
    const s = report.summary;
    const sections: SectionSummary[] = [
        {
            key: "dns",
            label: "DNS",
            anchor: "dns-details",
            grade: s?.dns_grade,
            score: s?.dns_score,
            unavailable: false,
        },
        {
            key: "authentication",
            label: "Authentication",
            anchor: "authentication-details",
            grade: s?.authentication_grade,
            score: s?.authentication_score,
            unavailable: hasNoAuthenticationResults(report.authentication),
        },
        {
            key: "blacklist",
            label: "Blacklists",
            anchor: "rbl-details",
            grade: s?.blacklist_grade,
            score: s?.blacklist_score,
            unavailable: hasNoBlacklistResults(report),
        },
        {
            key: "headers",
            label: "Headers",
            anchor: "header-details",
            grade: s?.header_grade,
            score: s?.header_score,
            unavailable: false,
        },
        {
            key: "spam",
            label: "Spam filters",
            anchor: "spam-details",
            grade: s?.spam_grade,
            score: s?.spam_score,
            unavailable: hasNoSpamResults(report),
        },
        {
            key: "content",
            label: "Content",
            anchor: "content-details",
            grade: s?.content_grade,
            score: s?.content_score,
            unavailable: false,
        },
    ];

    if (s?.attachments_grade) {
        sections.push({
            key: "attachments",
            label: "Attachments",
            anchor: "attachment-details",
            grade: s.attachments_grade,
            score: s.attachments_score,
            unavailable: false,
        });
    }

    return sections;
}

/** Every list of an object of issues by check, in one. */
function flatten(byCheck: Partial<Record<string, Issue[]>> | undefined): Issue[] {
    return Object.values(byCheck ?? {}).flatMap((issues) => issues ?? []);
}

/**
 * Everything the analyser found to change in one section. The spam filters report none:
 * their verdicts are what they found, which spamStatus reads.
 */
export function sectionIssues(report: Report, key: SectionKey): Issue[] {
    switch (key) {
        case "dns":
            return flatten(report.dns_results?.issues);
        case "authentication":
            return flatten(report.authentication?.issues);
        case "blacklist":
            return [
                ...flatten(report.blacklist_issues),
                ...(report.domain_reputation?.issues?.sources ?? []),
            ];
        case "headers":
            return flatten(report.header_analysis?.issues);
        case "content":
            return contentIssues(report.content_analysis);
        case "attachments":
            return (report.attachment_analysis?.attachments ?? []).flatMap((a) => a.issues ?? []);
        case "spam":
            return [];
    }
}

export type StatusTone = "success" | "info" | "warning" | "danger" | "muted";

export interface SectionStatus {
    label: string;
    tone: StatusTone;
    /** Whether the section has something to change: an open section is one to read. */
    needsAttention: boolean;
}

/**
 * How many changes the issues call for: the same defect with the same advice is one change,
 * however many records, links or lists it is found on.
 */
function changes(issues: Issue[]): number {
    return groupByChange(issues).length;
}

/**
 * What a section's header says before it is opened. A section that only passed says so and
 * stays folded; one with something to change says how many and opens.
 */
export function sectionStatus(issues: Issue[], unavailable = false, score?: number): SectionStatus {
    if (unavailable) {
        return { label: "Not checked", tone: "muted", needsAttention: false };
    }

    const actionable = issues.filter(isActionable);
    if (actionable.length > 0) {
        const grave = actionable.some((i) => i.severity === "critical" || i.severity === "high");
        return {
            label: `${changes(actionable)} to fix`,
            tone: grave ? "danger" : "warning",
            needsAttention: true,
        };
    }

    if (issues.length > 0) {
        const n = changes(issues);
        return {
            label: `${n} suggestion${n > 1 ? "s" : ""}`,
            tone: "info",
            needsAttention: false,
        };
    }

    // Points can go to a check that has nothing to suggest about it (a verdict the receiver
    // did not explain): claiming that everything passed would contradict the score next to it.
    if (score !== undefined && score < 100) {
        return { label: "No issue found", tone: "success", needsAttention: false };
    }

    return { label: "All checks passed", tone: "success", needsAttention: false };
}

/**
 * What the spam section says before it is opened, read off the verdicts of the filters as
 * their own cards show them: a filter classifying the message as spam, or one whose score
 * cost points. Nothing to say when both let the message through untouched, which leaves the
 * section to the general rule.
 */
export function spamStatus(
    report: Pick<Report, "spamassassin" | "rspamd">,
): SectionStatus | undefined {
    const verdicts = [report.spamassassin, report.rspamd].filter((v) => v !== undefined);

    if (verdicts.some((v) => v.is_spam)) {
        return { label: "Classified as spam", tone: "danger", needsAttention: true };
    }

    const lowest = Math.min(...verdicts.map((v) => v.deliverability_score ?? 100));
    if (lowest < 100) {
        return {
            label: "Spam score raised",
            tone: lowest < 50 ? "danger" : "warning",
            needsAttention: true,
        };
    }

    return undefined;
}

/** How each section of a report reads once folded. */
export function sectionStatuses(report: Report): Partial<Record<SectionKey, SectionStatus>> {
    const statuses: Partial<Record<SectionKey, SectionStatus>> = {};
    for (const section of sectionSummaries(report)) {
        statuses[section.key] =
            (section.key === "spam" && !section.unavailable ? spamStatus(report) : undefined) ??
            sectionStatus(sectionIssues(report, section.key), section.unavailable, section.score);
    }
    return statuses;
}
