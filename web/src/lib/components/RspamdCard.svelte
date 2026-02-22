<script lang="ts">
    import type { RspamdResult } from "$lib/api/types.gen";
    import { getScoreColorClass } from "$lib/score";
    import { theme } from "$lib/stores/theme";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        rspamd: RspamdResult;
    }

    let { rspamd }: Props = $props();

    // Derive effective action from score vs known rspamd default thresholds.
    // The action header is unreliable in milter setups (always "no action").
    const RSPAMD_GREYLIST_THRESHOLD = 4;
    const RSPAMD_ADD_HEADER_THRESHOLD = 6;

    const effectiveAction = $derived.by(() => {
        const rejectThreshold = rspamd.threshold > 0 ? rspamd.threshold : 15;
        if (rspamd.score >= rejectThreshold)
            return { label: "Reject", cls: "bg-danger" };
        if (rspamd.score >= RSPAMD_ADD_HEADER_THRESHOLD)
            return { label: "Add header", cls: "bg-warning text-dark" };
        if (rspamd.score >= RSPAMD_GREYLIST_THRESHOLD)
            return { label: "Greylist", cls: "bg-warning text-dark" };
        return { label: "No action", cls: "bg-success" };
    });
</script>

<div class="card shadow-sm" id="rspamd-details">
    <div class="card-header {$theme === 'light' ? 'bg-white' : 'bg-dark'}">
        <h4 class="mb-0 d-flex justify-content-between align-items-center">
            <span>
                <i class="bi bi-shield-exclamation me-2"></i>
                rspamd Analysis
            </span>
            <span>
                {#if rspamd.deliverability_score !== undefined}
                    <span class="badge bg-{getScoreColorClass(rspamd.deliverability_score)}">
                        {rspamd.deliverability_score}%
                    </span>
                {/if}
                {#if rspamd.deliverability_grade !== undefined}
                    <GradeDisplay grade={rspamd.deliverability_grade} size="small" />
                {/if}
            </span>
        </h4>
    </div>
    <div class="card-body">
        <div class="row mb-3">
            <div class="col-md-4">
                <strong>Score:</strong>
                <span class={rspamd.is_spam ? "text-danger" : "text-success"}>
                    {rspamd.score.toFixed(2)} / {rspamd.threshold.toFixed(1)}
                </span>
            </div>
            <div class="col-md-4">
                <strong>Classified as:</strong>
                <span class="badge {rspamd.is_spam ? 'bg-danger' : 'bg-success'} ms-2">
                    {rspamd.is_spam ? "SPAM" : "HAM"}
                </span>
            </div>
            <div class="col-md-4">
                <strong>Action:</strong>
                <span class="badge {effectiveAction.cls} ms-2">
                    {effectiveAction.label}
                </span>
            </div>
        </div>

        {#if rspamd.symbols && Object.keys(rspamd.symbols).length > 0}
            <div class="mb-3">
                <div class="table-responsive mt-2">
                    <table class="table table-sm table-hover">
                        <thead>
                            <tr>
                                <th>Symbol</th>
                                <th class="text-end">Score</th>
                                <th>Parameters</th>
                            </tr>
                        </thead>
                        <tbody>
                            {#each Object.entries(rspamd.symbols).sort(([, a], [, b]) => b.score - a.score) as [symbolName, symbol]}
                                <tr
                                    class={symbol.score > 0
                                        ? "table-warning"
                                        : symbol.score < 0
                                          ? "table-success"
                                          : ""}
                                >
                                    <td class="font-monospace">{symbolName}</td>
                                    <td class="text-end">
                                        <span
                                            class={symbol.score > 0
                                                ? "text-danger fw-bold"
                                                : symbol.score < 0
                                                  ? "text-success fw-bold"
                                                  : "text-muted"}
                                        >
                                            {symbol.score > 0 ? "+" : ""}{symbol.score.toFixed(2)}
                                        </span>
                                    </td>
                                    <td class="small text-muted">{symbol.params ?? ""}</td>
                                </tr>
                            {/each}
                        </tbody>
                    </table>
                </div>
            </div>
        {/if}
    </div>
</div>

<style>
    /* Darker table colors in dark mode */
    :global([data-bs-theme="dark"]) .table-warning {
        --bs-table-bg: rgba(255, 193, 7, 0.2);
        --bs-table-border-color: rgba(255, 193, 7, 0.3);
    }

    :global([data-bs-theme="dark"]) .table-success {
        --bs-table-bg: rgba(25, 135, 84, 0.2);
        --bs-table-border-color: rgba(25, 135, 84, 0.3);
    }
</style>
