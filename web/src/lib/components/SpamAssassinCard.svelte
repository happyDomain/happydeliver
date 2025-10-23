<script lang="ts">
    import type { SpamAssassinResult } from "$lib/api/types.gen";
    import { getScoreColorClass } from "$lib/score";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        spamassassin: SpamAssassinResult;
        spamGrade: string;
        spamScore: number;
    }

    let { spamassassin, spamGrade, spamScore }: Props = $props();
</script>

<div class="card shadow-sm" id="spam-details">
    <div class="card-header bg-white">
        <h4 class="mb-0 d-flex justify-content-between align-items-center">
            <span>
                <i class="bi bi-bug me-2"></i>
                SpamAssassin Analysis
            </span>
            <span>
                {#if spamScore !== undefined}
                    <span class="badge bg-{getScoreColorClass(spamScore)}">
                        {spamScore}%
                    </span>
                {/if}
                {#if spamGrade !== undefined}
                    <GradeDisplay grade={spamGrade} size="small" />
                {/if}
            </span>
        </h4>
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

        {#if spamassassin.test_details && Object.keys(spamassassin.test_details).length > 0}
            <div class="mb-3">
                <div class="table-responsive mt-2">
                    <table class="table table-sm table-hover">
                        <thead>
                            <tr>
                                <th>Test Name</th>
                                <th class="text-end">Score</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {#each Object.entries(spamassassin.test_details) as [testName, detail]}
                                <tr class={detail.score > 0 ? 'table-warning' : detail.score < 0 ? 'table-success' : ''}>
                                    <td class="font-monospace">{testName}</td>
                                    <td class="text-end">
                                        <span class={detail.score > 0 ? 'text-danger fw-bold' : detail.score < 0 ? 'text-success fw-bold' : 'text-muted'}>
                                            {detail.score > 0 ? '+' : ''}{detail.score.toFixed(1)}
                                        </span>
                                    </td>
                                    <td class="small">{detail.description || ''}</td>
                                </tr>
                            {/each}
                        </tbody>
                    </table>
                </div>
            </div>
        {:else if spamassassin.tests && spamassassin.tests.length > 0}
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
                <summary class="cursor-pointer fw-bold">Raw Report</summary>
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
