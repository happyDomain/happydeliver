<script lang="ts">
    interface Props {
        /** Anchor, so that anything pointing at this finding's advice has a target. */
        id?: string;
        /** What the finding is about: the defect for a content issue, the header's name for a header one. */
        title: string;
        severity: "critical" | "high" | "medium" | "low" | "info";
        message: string;
        /** Where it was found (a URL, a file name) when the finding names one. */
        location?: string;
        /** What to change, and what it costs not to. */
        advice?: string;
        /**
         * Who observed it, when it was not happyDeliver reading the message itself.
         * Shown with the symbol so the reader can look it up.
         */
        observer?: string;
        symbol?: string;
        /**
         * Other observers that reported the same defect. The finding is reported once; their
         * agreement is a reinforcement, not a second alert, so it goes in the same block.
         */
        corroboratedBy?: string[];
    }

    let {
        id,
        title,
        severity,
        message,
        location,
        advice,
        observer,
        symbol,
        corroboratedBy,
    }: Props = $props();

    // The colour is the whole of what severity says here: critical and high both mean the
    // message has a real problem, and naming the level again in a badge beside an alert that
    // is already red tells the reader nothing the red has not.
    const alertClass = $derived(
        severity === "critical" || severity === "high"
            ? "danger"
            : severity === "medium"
              ? "warning"
              : "info",
    );
</script>

<div {id} class="alert alert-{alertClass} py-2 px-3 mb-2">
    <div>
        <strong>{title}</strong>
        {#if observer}
            <span class="badge bg-secondary-subtle text-secondary-emphasis ms-1 fw-normal">
                via {observer}{#if symbol}
                    <code class="ms-1">{symbol}</code>
                {/if}
            </span>
        {/if}
        <div class="small">{message}</div>
        {#if location}
            <div class="small text-muted text-break">{location}</div>
        {/if}
        {#if advice}
            <div class="small mt-1">
                <i class="bi bi-lightbulb me-1"></i>
                {advice}
            </div>
        {/if}
        {#if corroboratedBy && corroboratedBy.length > 0}
            <div class="small text-muted mt-1">
                <i class="bi bi-check2-all me-1"></i>
                Also reported by
                {#each corroboratedBy as other, i (other)}
                    {#if i > 0},{/if}
                    <code>{other}</code>
                {/each}
            </div>
        {/if}
    </div>
</div>
