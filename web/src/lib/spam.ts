import type { Report } from "$lib/api/types.gen";

/**
 * True when no spam filter (SpamAssassin nor rspamd) produced a result for this message.
 *
 * This is not a sender problem: some receivers (Gmail, for instance) never run
 * SpamAssassin/rspamd directly, so there is nothing to grade. Whether these run depends on
 * this instance's mail infrastructure, not on the analysed email.
 */
export function hasNoSpamResults(report?: Pick<Report, "spamassassin" | "rspamd">): boolean {
    if (!report) return true;

    return !report.spamassassin && !report.rspamd;
}

/**
 * Short explanation of why no spam grade can be shown, suitable for a tooltip.
 */
export function noSpamResultsTitle(): string {
    return "Neither SpamAssassin nor rspamd produced a result for this message, so no spam grade can be computed. This depends on this instance's mail infrastructure, not on the analysed email.";
}
