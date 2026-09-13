import type { ContentIssue } from "$lib/api/types.gen";

/**
 * Readable name for a content issue type.
 *
 * The report used to print the raw enum ("missing_alt", "unreplaced_template"), which reads
 * as a database value rather than as a finding. The label is what a reader sees as the title
 * of the alert, so it names the defect, not the code.
 */
const contentIssueLabels: Record<ContentIssue["type"], string> = {
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
};

export function contentIssueLabel(type: ContentIssue["type"]): string {
    // A type the API added and the front end has not caught up with still has to read as
    // something: fall back on the enum with its underscores opened up.
    return contentIssueLabels[type] ?? type.replace(/_/g, " ");
}

/**
 * Who observed an issue, phrased for a reader.
 *
 * An issue with no source is one happyDeliver found by reading the message itself, which is
 * the default and needs no mention. Only a finding that came from the spam filter says so,
 * because that tells the reader where to go and look it up.
 */
export function issueObserver(issue: Pick<ContentIssue, "source">): string | undefined {
    return issue.source === "rspamd" ? "rspamd" : undefined;
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
export function adviceAnchorsBySymbol(issues?: ContentIssue[]): Record<string, string> {
    const anchors: Record<string, string> = {};

    issues?.forEach((issue, index) => {
        const anchor = contentIssueAnchor(index);

        if (issue.symbol) anchors[issue.symbol] = anchor;
        for (const other of issue.corroborated_by ?? []) anchors[other] = anchor;
    });

    return anchors;
}
