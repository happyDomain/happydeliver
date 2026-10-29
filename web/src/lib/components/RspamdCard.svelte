<script lang="ts">
    import type { RspamdResult, SpamTestDetail } from "#lib/api/types.gen.js";
    import { spamFilterSites } from "#lib/docs.js";
    import { formatRuleScore } from "#lib/spam.js";
    import CheckCard from "./CheckCard.svelte";
    import SpamRuleList from "./SpamRuleList.svelte";
    import SpamEngine from "./SpamEngine.svelte";
    import type { GaugeStep } from "./SpamScoreGauge.svelte";

    interface Props {
        rspamd: RspamdResult;
        /**
         * Symbol to the anchor of the content check showing its advice, for the symbols
         * that produced one.
         */
        adviceAnchors?: Record<string, string>;
    }

    let { rspamd, adviceAnchors = {} }: Props = $props();

    // rspamd's built-in action ladder, used to derive the action the message
    // would have triggered: the action header is unreliable in milter setups
    // (always "no action").
    const RSPAMD_GREYLIST_THRESHOLD = 4;
    const RSPAMD_ADD_HEADER_THRESHOLD = 6;
    const RSPAMD_DEFAULT_REJECT_THRESHOLD = 15;

    // The reported threshold is the score at which that instance rejects, so
    // prefer it: hardcoding rspamd's default would mislabel an instance that
    // rejects elsewhere.
    const rejectThreshold = $derived(rspamd.threshold ?? RSPAMD_DEFAULT_REJECT_THRESHOLD);

    // The steps below the reject threshold only: an instance rejecting from 5 never
    // gets to add a header at 6.
    const steps = $derived<GaugeStep[]>([
        ...[
            { at: RSPAMD_GREYLIST_THRESHOLD, label: "Greylist", zone: "Greylisted" },
            { at: RSPAMD_ADD_HEADER_THRESHOLD, label: "Add header", zone: "Spam folder" },
        ].filter((s) => s.at < rejectThreshold),
        { at: rejectThreshold, label: "Reject", zone: "Rejected" },
    ]);

    // What becomes of the message, in the words the gauge uses for the stretch it is in.
    const DELIVERED = "Delivered";
    const outcome = $derived(
        [...steps].reverse().find((s) => rspamd.score >= s.at)?.zone ?? DELIVERED,
    );

    const symbols = $derived(Object.entries(rspamd.symbols ?? {}));

    // What pushed the message towards spam, worst first: the symbols to act on. Each one
    // is something to improve even when the total costs nothing, since they are listed apart
    // from what lowered the score: FORGED_SENDER at +0.30 is still a forged sender.
    const scoring = $derived(
        symbols.filter(([, s]) => s.score > 0).sort(([, a], [, b]) => b.score - a.score),
    );
    // What lowered the score: in the sender's favour, so folded.
    const helping = $derived(
        symbols.filter(([, s]) => s.score < 0).sort(([, a], [, b]) => a.score - b.score),
    );
    // A symbol scoring zero neither helped nor hurt: rspamd raises a great many of
    // them to record that a check ran and had nothing to say (ARC_NA, R_SPF_NA,
    // DMARC_NA) or simply to trace what it saw (MIME_TRACE, DKIM_TRACE, ASN). On an
    // ordinary message they outnumber the rest several times over and bury it.
    //
    // They are folded away rather than dropped: "the check ran and found nothing" is
    // worth being able to look up, and a reader chasing one symbol in particular
    // needs to find it here. Sorted by name, since they have no score to rank them by.
    const quiet = $derived(
        symbols.filter(([, s]) => s.score === 0).sort(([a], [b]) => a.localeCompare(b)),
    );

    /** The first symbols of a list, as a folded row says them. */
    function names(rules: [string, SpamTestDetail][], limit = 3): string {
        const shown = rules
            .slice(0, limit)
            .map(([name, s]) => `${name} ${formatRuleScore(s.score, 2)}`)
            .join(", ");
        return rules.length > limit ? `${shown} and ${rules.length - limit} more` : shown;
    }

    const plural = (n: number, word: string) => `${n} ${word}${n > 1 ? "s" : ""}`;
</script>

<SpamEngine
    id="rspamd-details"
    name="rspamd"
    subject={rspamd.server}
    score={rspamd.score}
    {steps}
    base={DELIVERED}
    verdict={outcome}
    isSpam={rspamd.is_spam}
    deliverabilityScore={rspamd.deliverability_score}
    deliverabilityGrade={rspamd.deliverability_grade}
    site={spamFilterSites.rspamd}
    about="rspamd adds up the weight of every symbol it raises, then acts by steps: greylisting delays the message, an added header has it filed as spam, and from the last step on it is refused.{rspamd.threshold ===
    undefined
        ? " This instance did not say where it rejects: the threshold shown is rspamd's default."
        : ''}"
>
    {#if symbols.length > 0}
        <CheckCard
            title="Against the message"
            status={scoring.length === 0 ? "pass" : rspamd.is_spam ? "fail" : "improve"}
            summary={scoring.length > 0 ? names(scoring) : "No symbol counted against it"}
            tag={scoring.length > 0 ? plural(scoring.length, "symbol") : undefined}
            open={scoring.length > 0}
        >
            {#if scoring.length > 0}
                <div class="card-body">
                    <SpamRuleList rules={scoring} digits={2} {adviceAnchors} />
                </div>
            {/if}
        </CheckCard>

        {#if helping.length > 0}
            <CheckCard
                title="In your favour"
                status="pass"
                summary={names(helping)}
                tag={plural(helping.length, "symbol")}
            >
                <div class="card-body">
                    <SpamRuleList rules={helping} digits={2} {adviceAnchors} />
                </div>
            </CheckCard>
        {/if}

        {#if quiet.length > 0}
            <CheckCard
                title="Scored nothing"
                status="neutral"
                summary={quiet.map(([name]) => name).join(", ")}
                tag={plural(quiet.length, "symbol")}
            >
                <div class="card-body">
                    <SpamRuleList rules={quiet} digits={2} {adviceAnchors} />
                </div>
            </CheckCard>
        {/if}
    {/if}
</SpamEngine>
