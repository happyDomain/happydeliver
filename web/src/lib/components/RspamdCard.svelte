<script lang="ts">
    import type { RspamdResult } from "#lib/api/types.gen.js";
    import { getScoreColorClass } from "#lib/score.js";
    import CheckCard from "./CheckCard.svelte";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        rspamd: RspamdResult;
        /**
         * Symbol to the anchor of the content finding that carries its advice, for the symbols
         * that produced one. Without it the table is a list of names and numbers: a reader
         * seeing ZERO_FONT at +1.00 has no way of knowing that what to do about it is written
         * out further down the page.
         */
        adviceAnchors?: Record<string, string>;
        open?: boolean;
    }

    let { rspamd, adviceAnchors = {}, open }: Props = $props();

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

    const effectiveAction = $derived.by(() => {
        if (rspamd.score >= rejectThreshold) return { label: "Reject", cls: "bg-danger" };
        if (rspamd.score >= RSPAMD_ADD_HEADER_THRESHOLD)
            return { label: "Add header", cls: "bg-warning" };
        if (rspamd.score >= RSPAMD_GREYLIST_THRESHOLD)
            return { label: "Greylist", cls: "bg-warning" };
        return { label: "No action", cls: "bg-success" };
    });

    const symbols = $derived(Object.entries(rspamd.symbols ?? {}));

    // What pushed the message towards spam, worst first: the symbols to act on.
    const scoring = $derived(
        symbols.filter(([, symbol]) => symbol.score > 0).sort(([, a], [, b]) => b.score - a.score),
    );

    // What lowered the score: in the sender's favour, so folded with the neutral ones below.
    const helping = $derived(
        symbols.filter(([, symbol]) => symbol.score < 0).sort(([, a], [, b]) => a.score - b.score),
    );

    const checkStatus = $derived(
        rspamd.is_spam ? "fail" : (rspamd.deliverability_score ?? 100) < 100 ? "improve" : "pass",
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
        symbols.filter(([, symbol]) => symbol.score === 0).sort(([a], [b]) => a.localeCompare(b)),
    );
</script>

{#snippet symbolRows(rows: typeof symbols)}
    {#each rows as [symbolName, symbol] (symbolName)}
        <tr class={symbol.score > 0 ? "table-warning" : symbol.score < 0 ? "table-success" : ""}>
            <td>
                <span class="font-monospace">{symbolName}</span>
                {#if adviceAnchors[symbolName]}
                    <!-- The symbol itself stays plain text: it is a name to read, not
                         somewhere to go. Only the lightbulb leads to the advice. -->
                    <a
                        class="ms-1"
                        href="#{adviceAnchors[symbolName]}"
                        title="This symbol produced a finding with advice, further down in Content Analysis"
                        aria-label="Read the advice for {symbolName}"
                    >
                        <i class="bi bi-lightbulb" aria-hidden="true"></i>
                    </a>
                {/if}
                {#if symbol.params}
                    <small class="d-block text-muted">
                        {symbol.params}
                    </small>
                {/if}
            </td>
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
            <td class="small text-muted">{symbol.description ?? ""}</td>
        </tr>
    {/each}
{/snippet}

<CheckCard
    id="rspamd-details"
    class="mb-0 h-100"
    title="rspamd"
    status={checkStatus}
    summary="{rspamd.score.toFixed(1)}{rspamd.threshold !== undefined
        ? ` / ${rspamd.threshold.toFixed(1)}`
        : ''}, {rspamd.is_spam ? 'spam' : 'not spam'}"
    open={open ?? checkStatus !== "pass"}
>
    {#snippet aside()}
        {#if rspamd.deliverability_score !== undefined}
            <span class="badge bg-{getScoreColorClass(rspamd.deliverability_score)}">
                {rspamd.deliverability_score}%
            </span>
        {/if}
        {#if rspamd.deliverability_grade !== undefined}
            <GradeDisplay grade={rspamd.deliverability_grade} size="inline" />
        {/if}
    {/snippet}
    <div class="card-body">
        <div class="row mb-3">
            <div class="col-md-4">
                <strong>Score:</strong>
                <!-- Absent when rspamd reported no threshold: show the score alone
                     rather than a boundary this instance may not apply. -->
                <span class={rspamd.is_spam ? "text-danger" : "text-success"}>
                    {rspamd.score.toFixed(2)}{#if rspamd.threshold !== undefined}
                        / {rspamd.threshold.toFixed(1)}{/if}
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

        {#if symbols.length > 0}
            <div class="mb-3">
                {#if scoring.length > 0}
                    <div class="table-responsive mt-2">
                        <table class="table table-sm table-hover">
                            <thead>
                                <tr>
                                    <th>Symbol</th>
                                    <th class="text-end">Score</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
                                {@render symbolRows(scoring)}
                            </tbody>
                        </table>
                    </div>
                {:else}
                    <p class="text-muted small mb-0 mt-2">
                        <i class="bi bi-check-circle-fill text-success me-1"></i>
                        No symbol counted against the message.
                    </p>
                {/if}

                {#if helping.length > 0}
                    <details class="passed-items mt-2">
                        <summary>
                            {helping.length} symbol{helping.length > 1 ? "s" : ""} in your favour
                        </summary>
                        <div class="table-responsive mt-2">
                            <table class="table table-sm table-hover">
                                <thead>
                                    <tr>
                                        <th>Symbol</th>
                                        <th class="text-end">Score</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {@render symbolRows(helping)}
                                </tbody>
                            </table>
                        </div>
                    </details>
                {/if}

                {#if quiet.length > 0}
                    <details class="passed-items mt-2">
                        <summary>
                            {quiet.length} symbol{quiet.length > 1 ? "s" : ""} that scored nothing
                        </summary>
                        <div class="table-responsive mt-2">
                            <table class="table table-sm table-hover">
                                <thead>
                                    <tr>
                                        <th>Symbol</th>
                                        <th class="text-end">Score</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {@render symbolRows(quiet)}
                                </tbody>
                            </table>
                        </div>
                    </details>
                {/if}
            </div>
        {/if}

        {#if rspamd.report}
            <details class="mt-3">
                <summary class="cursor-pointer fw-bold">Raw Report</summary>
                <pre class="mt-2 small p-3 rounded">{rspamd.report}</pre>
            </details>
        {/if}
    </div>
</CheckCard>

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
