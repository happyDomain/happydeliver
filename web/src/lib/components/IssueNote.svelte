<script lang="ts">
    import type { Issue } from "#lib/api/types.gen.js";
    import { issueLabel, issueObserver } from "#lib/issues.js";

    interface Props {
        issue: Issue;
        /**
         * What was observed, when the note stands for several issues shown on rows below it:
         * how many rows it is about. Defaults to the issue's own message.
         */
        detail?: string;
        /** What fixing it brings back, when the note stands for several issues. */
        penalty?: number;
    }

    // Not a default value of the prop: that one is read once, and the note would keep the
    // penalty of the issue it was first given.
    let { issue, detail, penalty: sharedPenalty }: Props = $props();
    const penalty = $derived(sharedPenalty ?? issue.penalty);

    const observer = $derived(issueObserver(issue));
    const shownDetail = $derived(
        detail ?? `${issue.message}${observer ? ` (reported by ${observer})` : ""}`,
    );

    // The same tones as the icon of the check the note sits in, so the two read as one.
    const tone = $derived(
        issue.severity === "critical" || issue.severity === "high"
            ? "danger"
            : issue.severity === "info"
              ? "info"
              : "warning",
    );
</script>

<!-- What is wrong and what to change, worded by the analyser: the evidence follows, below the
     note, in the check itself. -->
<div
    class="issue-note border-start border-3 border-{tone} rounded-end py-2 px-3 mb-3"
    style:--note-rgb="var(--bs-{tone}-rgb)"
>
    <div class="d-flex flex-wrap align-items-baseline column-gap-2">
        <span class="fw-semibold text-{tone}-emphasis">{issueLabel(issue.type)}</span>
        {#if penalty}
            <!-- What fixing it alone brings back, in points of the section score -->
            <span class="small text-body-secondary text-nowrap" title="Points of the section score"
                >−{penalty} pts</span
            >
        {/if}
    </div>
    <div class="small">{shownDetail}</div>
    {#if issue.advice}
        <div class="small mt-1">
            <i class="bi bi-arrow-right-short" aria-hidden="true"></i>
            <span class="visually-hidden">To fix:</span>
            {issue.advice}
        </div>
    {/if}
</div>

<style>
    /* A wash of the tone, lighter than Bootstrap's subtle backgrounds, so the note reads as one
       block without competing with the alerts. */
    .issue-note {
        background-color: rgba(var(--note-rgb), 0.06);
    }
</style>
