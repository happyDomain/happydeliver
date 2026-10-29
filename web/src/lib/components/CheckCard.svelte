<script lang="ts" module>
    /**
     * How a check came out, which sets its icon and whether it starts unfolded.
     * "improve" passed, but has a change to suggest; "neutral" is not graded at all.
     */
    export type CheckStatus = "pass" | "improve" | "warn" | "fail" | "info" | "neutral";

    const icons: Record<CheckStatus, string> = {
        pass: "bi-check-circle-fill text-success",
        improve: "bi-arrow-up-circle-fill text-warning",
        warn: "bi-exclamation-triangle-fill text-warning",
        fail: "bi-x-circle-fill text-danger",
        info: "bi-info-circle-fill text-info",
        neutral: "bi-circle text-secondary",
    };

    const labels: Record<CheckStatus, string> = {
        pass: "Passed",
        improve: "Can be improved",
        warn: "Warning",
        fail: "Failed",
        info: "Information",
        neutral: "Not graded",
    };
</script>

<script lang="ts">
    import type { Snippet } from "svelte";
    import type { ClassValue } from "svelte/elements";

    import type { DocLink } from "#lib/docs.js";
    import DocLinks from "./DocLinks.svelte";

    interface Props {
        id?: string;
        title: string;
        status: CheckStatus;
        /** Overrides the status icon, for a check that is about something rather than graded. */
        icon?: string;
        /** One line telling what was found, so a folded check still says it. */
        summary?: string;
        /** Shows the summary only while the check is folded, when its body already says it. */
        summaryFoldedOnly?: boolean;
        /** Short name of the mechanism, on the right of the header: SPF, PTR, MX… */
        tag?: string;
        /** Replaces the tag on the right of the header. */
        aside?: Snippet;
        /** Where the standard describes what this check verifies. */
        docs?: DocLink[];
        /** Defaults to unfolded when there is something to act on. */
        open?: boolean;
        class?: ClassValue;
        children?: Snippet;
    }

    let {
        id,
        title,
        status,
        icon,
        summary,
        summaryFoldedOnly = false,
        tag,
        aside,
        docs,
        open,
        class: className = "mb-3",
        children,
    }: Props = $props();

    const startOpen = $derived(open ?? (status === "fail" || status === "warn"));
</script>

<details class={["card check-card", className]} {id} open={startOpen}>
    <summary class="card-header d-flex align-items-center gap-3 py-2 px-3 user-select-none">
        <i
            class="bi {icon ?? icons[status]} fs-5 flex-shrink-0"
            role="img"
            aria-label={labels[status]}
            title={labels[status]}
        ></i>
        <span
            class="flex-grow-1 overflow-hidden d-flex flex-wrap align-items-baseline column-gap-3"
        >
            <h5 class="mb-0">{title}</h5>
            {#if summary}
                <span
                    class={[
                        "small text-body-secondary text-truncate mw-100",
                        summaryFoldedOnly && "check-summary-folded",
                    ]}>{summary}</span
                >
            {/if}
        </span>
        {#if aside}
            {@render aside()}
        {:else if tag}
            <span class="badge bg-secondary">{tag}</span>
        {/if}
        <i class="bi bi-chevron-down disclosure" aria-hidden="true"></i>
    </summary>
    {@render children?.()}
    {#if docs && docs.length > 0}
        <div class="card-footer">
            <DocLinks {docs} />
        </div>
    {/if}
</details>
