<script lang="ts">
    import type { SpamAssassinResult } from "$lib/api/types.gen";

    interface Props {
        spamassassin: SpamAssassinResult;
    }

    let { spamassassin }: Props = $props();
</script>

<div class="card">
    <div class="card-header bg-warning bg-opacity-10">
        <h5 class="mb-0 fw-bold">
            <i class="bi bi-bug me-2"></i>SpamAssassin Analysis
        </h5>
    </div>
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

        {#if spamassassin.tests && spamassassin.tests.length > 0}
            <div class="mb-2">
                <strong>Tests Triggered:</strong>
                <div class="mt-2">
                    {#each spamassassin.tests as test}
                        <span class="badge bg-light text-dark me-1 mb-1">{test}</span>
                    {/each}
                </div>
            </div>
        {/if}

        {#if spamassassin.report}
            <details class="mt-3">
                <summary class="cursor-pointer fw-bold">Full Report</summary>
                <pre class="mt-2 small bg-light p-3 rounded">{spamassassin.report}</pre>
            </details>
        {/if}
    </div>
</div>

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
