import type { Report } from "$lib/api/types.gen";

/**
 * True when no IP address could be extracted from the message to check against DNS
 * blacklists.
 *
 * This is not a sender problem: without a usable IP in the `Received` headers there is
 * nothing to look up, so the reported 100%/A+ would otherwise misleadingly read as "clean"
 * rather than "unchecked".
 */
export function hasNoBlacklistResults(report?: Pick<Report, "blacklists">): boolean {
    if (!report) return true;

    return !report.blacklists || Object.keys(report.blacklists).length === 0;
}

/**
 * Short explanation of why no blacklist grade can be shown, suitable for a tooltip.
 */
export function noBlacklistResultsTitle(): string {
    return "No IP address could be extracted from this message to check against DNS blacklists, so no grade can be computed.";
}
