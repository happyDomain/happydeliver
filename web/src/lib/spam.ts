import type { Report } from "#lib/api/types.gen.js";

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

/**
 * A rule's weight, signed. Filters weigh some rules a thousandth of a point to record that
 * they ran (SpamAssassin's RCVD_IN_DNSWL_NONE, -0.0001): rounded like the others they would
 * read as +0.0, which is neither true nor zero.
 */
export function formatRuleScore(score: number, digits = 1): string {
    const sign = score > 0 ? "+" : score < 0 ? "−" : "";
    const abs = Math.abs(score);
    const shown = abs > 0 && abs < 0.5 * 10 ** -digits ? abs.toPrecision(1) : abs.toFixed(digits);
    return `${sign}${shown}`;
}

/**
 * Rules in the order the filter's own report lists them, which groups those about the same
 * thing: SpamAssassin writes DKIM_SIGNED next to DKIM_VALID, and the +0.1 of one only reads
 * right beside the −0.1 of the other. The details come as an object, whose keys the API
 * sorts alphabetically, so the order is read back from the raw report; failing that, from
 * the list of rule names. A rule found in neither goes last, by name.
 */
export function inReportOrder<T>(
    rules: Record<string, T>,
    report?: string,
    names?: string[],
): [string, T][] {
    const rank = (name: string): number => {
        // Whole names only: DKIM_VALID is not the start of DKIM_VALID_AU.
        const match = report
            ? new RegExp(`(?<![\\w])${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w])`).exec(
                  report,
              )
            : null;
        if (match) return match.index;
        const listed = names?.indexOf(name) ?? -1;
        return listed >= 0 ? (report?.length ?? 0) + listed : Infinity;
    };
    return Object.entries(rules)
        .map(([name, rule]) => ({ name, rule, at: rank(name) }))
        .sort((a, b) => a.at - b.at || a.name.localeCompare(b.name))
        .map(({ name, rule }) => [name, rule]);
}
