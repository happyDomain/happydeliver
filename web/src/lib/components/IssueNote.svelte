<script lang="ts">
    import type { Issue } from "#lib/api/types.gen.js";
    import { issueLabel, issueObserver } from "#lib/issues.js";

    interface Props {
        issue: Issue;
    }

    let { issue }: Props = $props();

    const observer = $derived(issueObserver(issue));

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
    <div class="fw-semibold text-{tone}-emphasis">{issueLabel(issue.type)}</div>
    <div class="small">{issue.message}{observer ? ` (reported by ${observer})` : ""}</div>
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
