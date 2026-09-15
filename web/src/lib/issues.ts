import type { Issue } from "$lib/api/types.gen";

/**
 * Readable name for an issue type.
 *
 * The report used to print the raw enum ("missing_alt", "unreplaced_template"), which reads
 * as a database value rather than as a finding. The label is what a reader sees as the title
 * of the alert, so it names the defect, not the code.
 */
const issueLabels: Record<Issue["type"], string> = {
    broken_html: "Broken HTML",
    missing_alt: "Missing alt text",
    excessive_images: "Too many images",
    obfuscated_url: "Obfuscated URL",
    suspicious_link: "Suspicious link",
    dangerous_html: "Dangerous HTML",
    unreplaced_template: "Unreplaced merge field",
    truncated_body: "Body cut short",
    unreachable_link: "Unreachable link",
    excessive_redirects: "Too many redirections",
    hidden_text: "Hidden text",
    image_only_content: "Image-only content",
    attachment_risk: "Risky attachment",
    link_reputation: "Link reputation",
    homograph_url: "Look-alike URL",
    client_compat: "Client compatibility",
    text_html_mismatch: "Text and HTML out of sync",
    low_contrast: "Low contrast",
    sender_domain_mismatch: "Links off the sender's domain",
    // What a message carries alongside its body.
    malware_detected: "Malware detected",
    type_mismatch: "Content is not what it claims",
    double_extension: "Deceptive double extension",
    dangerous_extension: "Dangerous file extension",
    executable_content: "Executable attachment",
    scan_error: "Scanner could not answer",
    scan_skipped: "Not fully scanned",
};

export function issueLabel(type: Issue["type"]): string {
    // A type the API added and the front end has not caught up with still has to read as
    // something: fall back on the enum with its underscores opened up.
    return issueLabels[type] ?? type.replace(/_/g, " ");
}

/**
 * Readable name for the reading an issue answers.
 *
 * The category is what the report groups by, so this is a section heading rather than a
 * label on an alert: it names what the reader is about to be shown, not the enum the API
 * sent.
 */
const categoryLabels: Record<Issue["category"], string> = {
    security: "Security",
    deliverability: "Deliverability",
    content: "Content",
    rendering: "Rendering",
    accessibility: "Accessibility",
};

export function categoryLabel(category: Issue["category"]): string {
    return categoryLabels[category] ?? String(category).replace(/_/g, " ");
}

/**
 * The order the groups are read in, which is an editorial decision and not the alphabet:
 * what may harm whoever opens the message first, then what keeps it out of the inbox, then
 * what it says, then what it looks like, then the recipients it leaves out.
 *
 * A category absent from this list is not dropped: it is shown after the ones that are, so
 * that a reading the API adds before the front end catches up still reaches a reader.
 */
const categoryOrder: Issue["category"][] = [
    "security",
    "deliverability",
    "content",
    "rendering",
    "accessibility",
];

/**
 * How grave a finding is, as a number, so that the list can be put in that order.
 *
 * The alert's colour says the same thing, but only three ways: critical and high share one
 * red, low and info one blue. The order is what separates them, which is the other half of
 * why the severity is no longer named in a badge of its own.
 */
const severityRank: Record<Issue["severity"], number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
};

/** Anything the report shows in an alert: a content issue, a header one. */
type Severe = { severity: Issue["severity"] };

/**
 * Orders findings gravest first, leaving those the severity does not separate in the order
 * they were given. A severity this front end does not know sorts last rather than first, so
 * that a level the API adds cannot quietly take the top of every list.
 */
export function compareBySeverity(a: Severe, b: Severe): number {
    return (
        (severityRank[a.severity] ?? Number.MAX_SAFE_INTEGER) -
        (severityRank[b.severity] ?? Number.MAX_SAFE_INTEGER)
    );
}

/** One issue together with its position in html_issues, which is what its anchor is made of. */
export type PlacedIssue = { issue: Issue; index: number };

/**
 * The issues of one reading, in the order the checks reported them.
 *
 * The category is optional because a report is read long after it was produced: one written
 * before the analysis recorded a category carries none, and nothing can be recomputed for it
 * afterwards. The category comes from the check that reported the finding, and a stored issue
 * keeps only its type, which deliberately does not map onto one reading. Such issues are shown
 * as they always were, in one run under no heading.
 */
export type IssueGroup = {
    category?: Issue["category"];
    issues: PlacedIssue[];
};

/**
 * The issues grouped by the reading they answer, ready to be shown section by section.
 *
 * Each issue keeps the index it had in html_issues. That is not a convenience: the anchor of
 * an issue is made of that index (see contentIssueAnchor), and the rspamd symbol table links
 * to it through adviceAnchorsBySymbol. Grouping by position in the group instead would point
 * every one of those links at the wrong advice.
 *
 * Within a group the gravest findings come first: a reader opening a section is looking for
 * what to fix, and a section that opens on an informational remark buries it. Findings of
 * equal gravity keep the order the analysis produced them in, which is itself deliberate:
 * the checks run in the order their findings are meant to be read.
 *
 * A severity the front end does not know sorts last rather than first, so that a level the
 * API adds cannot quietly take the top of every section.
 */
export function groupIssuesByCategory(issues?: Issue[]): IssueGroup[] {
    const groups = new Map<Issue["category"] | undefined, PlacedIssue[]>();

    issues?.forEach((issue, index) => {
        // A report produced before the analysis recorded a reading carries none. It is
        // keyed under undefined rather than under a reading invented for it, and comes out
        // last, unheaded: the alternative is filing findings under a heading nobody
        // measured them against.
        const category = issue.category || undefined;

        const group = groups.get(category);
        if (group) group.push({ issue, index });
        else groups.set(category, [{ issue, index }]);
    });

    const known = categoryOrder.filter((category) => groups.has(category));
    const unknown = [...groups.keys()].filter(
        (category) => category !== undefined && !categoryOrder.includes(category),
    );
    const uncategorised = groups.has(undefined) ? [undefined] : [];

    return [...known, ...unknown, ...uncategorised].map((category) => ({
        category,
        // Array.prototype.sort is stable, which is what keeps the analysis's own order
        // between findings the severity does not separate.
        issues: (groups.get(category) ?? [])
            .slice()
            .sort((a, b) => compareBySeverity(a.issue, b.issue)),
    }));
}

/**
 * Who observed an issue, phrased for a reader.
 *
 * An issue with no source is one happyDeliver found by reading the message itself, which is
 * the default and needs no mention. Only a finding that came from elsewhere says so — the
 * spam filter, an antivirus engine — because that tells the reader where to go and look it
 * up.
 */
export function issueObserver(issue: Pick<Issue, "source">): string | undefined {
    return !issue.source || issue.source === "self" ? undefined : issue.source;
}

/**
 * Anchor of a content issue, so anything pointing at its advice has a stable target: the
 * rspamd symbol table below, or a link someone sends a colleague.
 */
export function contentIssueAnchor(index: number): string {
    return `content-issue-${index}`;
}

/**
 * Symbol to the anchor of the finding that carries its advice.
 *
 * A symbol reaches the report one of two ways: it raised a finding of its own, or it
 * corroborated one of ours. Either way advice for it sits in the content card, and the symbol
 * table has no way of saying so: a reader seeing ZERO_FONT at +1.00 cannot tell that an
 * explanation of what to do about it is waiting further down the page.
 */
export function adviceAnchorsBySymbol(issues?: Issue[]): Record<string, string> {
    const anchors: Record<string, string> = {};

    issues?.forEach((issue, index) => {
        const anchor = contentIssueAnchor(index);

        if (issue.symbol) anchors[issue.symbol] = anchor;
        for (const other of issue.corroborated_by ?? []) anchors[other] = anchor;
    });

    return anchors;
}
