<script lang="ts">
    import type { UpstreamSpamVerdictCardProps } from "./upstreamSpamVerdicts/index.js";
    import CheckCard from "./CheckCard.svelte";
    import FactRow from "./FactRow.svelte";
    import SpamEngine from "./SpamEngine.svelte";
    import VerdictFacts from "./VerdictFacts.svelte";

    let { verdict }: UpstreamSpamVerdictCardProps = $props();

    /** The details as rows: their shape is the filter's own, so each value is shown as is. */
    const facts = $derived(
        verdict.details !== null && typeof verdict.details === "object"
            ? Object.entries(verdict.details as Record<string, unknown>)
                  .filter(([, value]) => value !== undefined && value !== null && value !== "")
                  .map(([key, value]) => ({
                      key,
                      value: typeof value === "object" ? JSON.stringify(value) : String(value),
                  }))
            : [],
    );
</script>

<!-- A filter the interface has no card of its own for: its verdict, and its details as given. -->
<SpamEngine
    id="{verdict.filter}-details"
    name={verdict.name}
    steps={[]}
    base="Not spam"
    verdict={verdict.verdict}
    isSpam={verdict.is_spam}
    deliverabilityScore={verdict.deliverability_score}
    deliverabilityGrade={verdict.deliverability_grade}
    about="{verdict.name} wrote this verdict before this instance saw the message, whichever side of the exchange it filters: one against the message lowers the spam grade, one in its favour proves nothing and leaves the grade to the other filters."
>
    <CheckCard
        title="{verdict.name}'s verdict"
        status={verdict.is_spam ? "fail" : verdict.deliverability_grade ? "warn" : "pass"}
        summary={verdict.verdict}
        open={verdict.is_spam}
    >
        <div class="card-body">
            <VerdictFacts title="Reported by {verdict.name}">
                <FactRow label="Verdict" value={verdict.verdict} />
                {#each facts as fact (fact.key)}
                    <FactRow label={fact.key} value={fact.value} mono />
                {/each}
            </VerdictFacts>
        </div>
    </CheckCard>
</SpamEngine>
