<script lang="ts">
    import type { SpamAssassinResult, SpamTestDetail } from "#lib/api/types.gen.js";
    import { spamFilterSites } from "#lib/docs.js";
    import { formatRuleScore, inReportOrder } from "#lib/spam.js";
    import CheckCard from "./CheckCard.svelte";
    import SpamRuleList from "./SpamRuleList.svelte";
    import SpamEngine from "./SpamEngine.svelte";

    interface Props {
        spamassassin: SpamAssassinResult;
    }

    let { spamassassin }: Props = $props();

    // One list, in the order SpamAssassin reports them: it keeps the rules about the same
    // thing together, so a +0.1 for DKIM_SIGNED reads beside the -0.1 for DKIM_VALID that
    // cancels it, rather than as a fault on its own.
    const tests = $derived(
        inReportOrder(spamassassin.test_details ?? {}, spamassassin.report, spamassassin.tests),
    );

    // DKIM_SIGNED is there whenever the message carries a signature: it only tells something
    // when no DKIM_VALID comes to vouch for that signature.
    const dkimVouched = $derived(tests.some(([name]) => name === "DKIM_VALID"));

    // What pushed the message towards spam, worst first: what the folded row names.
    const raising = $derived(
        tests
            .filter(([name, t]) => t.score > 0 && !(name === "DKIM_SIGNED" && dkimVouched))
            .sort(([, a], [, b]) => b.score - a.score),
    );

    // The rules are what the verdict is made of, so they take its status: a rule adding a
    // tenth of a point does not call for a change when the score, all told, costs nothing.
    const rulesStatus = $derived(
        spamassassin.is_spam
            ? "fail"
            : (spamassassin.deliverability_score ?? (spamassassin.score > 0 ? 0 : 100)) < 100
              ? "improve"
              : "pass",
    );

    /** The first rules of a list, as a folded row says them. */
    function names(rules: [string, SpamTestDetail][], limit = 3): string {
        const shown = rules
            .slice(0, limit)
            .map(([name, t]) => `${name} ${formatRuleScore(t.score)}`)
            .join(", ");
        return rules.length > limit ? `${shown} and ${rules.length - limit} more` : shown;
    }

    const plural = (n: number, word: string) => `${n} ${word}${n > 1 ? "s" : ""}`;
</script>

<SpamEngine
    id="spamassassin-details"
    name="SpamAssassin"
    subject={spamassassin.version}
    score={spamassassin.score}
    steps={[{ at: spamassassin.required_score, label: "Spam", zone: "Spam" }]}
    base="Not spam"
    verdict={spamassassin.is_spam ? "Spam" : "Not spam"}
    isSpam={spamassassin.is_spam}
    deliverabilityScore={spamassassin.deliverability_score}
    deliverabilityGrade={spamassassin.deliverability_grade}
    site={spamFilterSites.spamassassin}
    about="SpamAssassin adds up the weight of every rule the message triggers. From the threshold on, the receiver files it as spam; below it, every point still makes the next filter less forgiving."
>
    {#if tests.length > 0}
        <CheckCard
            title="Rules"
            status={rulesStatus}
            summary={rulesStatus !== "pass"
                ? `Against the message: ${names(raising)}`
                : spamassassin.score < 0
                  ? `In the message's favour overall, ${formatRuleScore(spamassassin.score)}`
                  : "Nothing counted against the message"}
            tag={plural(tests.length, "rule")}
            open={rulesStatus !== "pass"}
        >
            <div class="card-body">
                <SpamRuleList rules={tests} />
            </div>
        </CheckCard>
    {:else if spamassassin.tests && spamassassin.tests.length > 0}
        <!-- Reports from before test_details was recorded carry only the rule names -->
        <CheckCard
            title="Rules triggered"
            status="neutral"
            summary={spamassassin.tests.join(", ")}
            tag={plural(spamassassin.tests.length, "rule")}
        >
            <div class="card-body">
                {#each spamassassin.tests as test (test)}
                    <span class="badge text-bg-light font-monospace me-1 mb-1">{test}</span>
                {/each}
            </div>
        </CheckCard>
    {/if}
</SpamEngine>
