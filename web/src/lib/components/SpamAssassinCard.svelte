<script lang="ts">
    import type { SpamAssassinResult, SpamTestDetail } from "#lib/api/types.gen.js";
    import { getScoreColorClass } from "#lib/score.js";
    import CheckCard from "./CheckCard.svelte";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        spamassassin: SpamAssassinResult;
        open?: boolean;
    }

    let { spamassassin, open }: Props = $props();

    const tests = $derived(Object.entries(spamassassin.test_details ?? {}));

    // DKIM_SIGNED is there whenever the message carries a signature: it only tells something
    // when no DKIM_VALID comes to vouch for that signature.
    const dkimVouched = $derived(tests.some(([name]) => name === "DKIM_VALID"));
    const harmless = ([name, t]: [string, SpamTestDetail]) =>
        t.score <= 0 || (name === "DKIM_SIGNED" && dkimVouched);

    // What pushed the message towards spam, worst first: the rules to act on. Those that
    // lowered the score or did nothing are the expected case and are folded away.
    const raising = $derived(
        tests.filter((r) => !harmless(r)).sort(([, a], [, b]) => b.score - a.score),
    );
    const others = $derived(tests.filter(harmless).sort(([, a], [, b]) => a.score - b.score));

    const checkStatus = $derived(
        spamassassin.is_spam
            ? "fail"
            : (spamassassin.deliverability_score ?? 100) < 100
              ? "improve"
              : "pass",
    );
</script>

<CheckCard
    id="spam-details"
    class="mb-0 h-100"
    title="SpamAssassin"
    status={checkStatus}
    summary="{spamassassin.score.toFixed(1)} / {spamassassin.required_score.toFixed(
        1,
    )}, {spamassassin.is_spam ? 'spam' : 'not spam'}"
    open={open ?? checkStatus !== "pass"}
>
    {#snippet aside()}
        {#if spamassassin.deliverability_score !== undefined}
            <span class="badge bg-{getScoreColorClass(spamassassin.deliverability_score)}">
                {spamassassin.deliverability_score}%
            </span>
        {/if}
        {#if spamassassin.deliverability_grade !== undefined}
            <GradeDisplay grade={spamassassin.deliverability_grade} size="inline" />
        {/if}
    {/snippet}
    <div class="card-body">
        <div class="row mb-3">
            <div class="col-md-6">
                <strong>Score:</strong>
                <span class={spamassassin.is_spam ? "text-danger" : "text-success"}>
                    {spamassassin.score.toFixed(2)} / {spamassassin.required_score.toFixed(1)}
                </span>
            </div>
            <div class="col-md-6">
                <strong>Classified as:</strong>
                <span class="badge {spamassassin.is_spam ? 'bg-danger' : 'bg-success'} ms-2">
                    {spamassassin.is_spam ? "SPAM" : "HAM"}
                </span>
            </div>
        </div>

        {#if tests.length > 0}
            {#if raising.length > 0}
                <p class="small text-muted mb-1">
                    Rules that raised the score, the ones weighing the most first:
                </p>
                {@render testTable(raising)}
            {:else}
                <p class="small text-muted mb-2">
                    <i class="bi bi-check-circle-fill text-success me-1"></i>
                    No rule counted against the message.
                </p>
            {/if}
            {#if others.length > 0}
                <details class="passed-items mb-2">
                    <summary>
                        {others.length} rule{others.length > 1 ? "s" : ""} in your favour or neutral
                    </summary>
                    <div class="mt-2">{@render testTable(others)}</div>
                </details>
            {/if}
        {:else if spamassassin.tests && spamassassin.tests.length > 0}
            <div class="mb-2">
                <strong>Tests Triggered:</strong>
                <div class="mt-2">
                    {#each spamassassin.tests as test (test)}
                        <span class="badge text-bg-light me-1 mb-1">{test}</span>
                    {/each}
                </div>
            </div>
        {/if}

        {#if spamassassin.report}
            <details class="mt-3">
                <summary class="cursor-pointer fw-bold">Raw Report</summary>
                <pre class="mt-2 small p-3 rounded">{spamassassin.report}</pre>
            </details>
        {/if}
    </div>
</CheckCard>

{#snippet testTable(rows: [string, SpamTestDetail][])}
    <div class="table-responsive">
        <table class="table table-sm table-hover mb-2">
            <thead>
                <tr>
                    <th>Test Name</th>
                    <th class="text-end">Score</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {#each rows as [testName, detail] (testName)}
                    <tr
                        class={detail.score > 0
                            ? "table-warning"
                            : detail.score < 0
                              ? "table-success"
                              : ""}
                    >
                        <td class="font-monospace">{testName}</td>
                        <td class="text-end">
                            <span
                                class={detail.score > 0
                                    ? "text-danger fw-bold"
                                    : detail.score < 0
                                      ? "text-success fw-bold"
                                      : "text-muted"}
                            >
                                {detail.score > 0 ? "+" : ""}{detail.score.toFixed(1)}
                            </span>
                        </td>
                        <td class="small">{detail.description || ""}</td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/snippet}

<style>
    .cursor-pointer {
        cursor: pointer;
    }

    details summary {
        user-select: none;
    }

    details summary:hover {
        color: var(--bs-primary);
    }
</style>
