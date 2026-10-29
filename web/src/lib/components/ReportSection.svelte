<script lang="ts">
    import type { Snippet } from "svelte";

    import type { SectionStatus } from "#lib/sections.js";
    import { getScoreColorClass } from "#lib/score.js";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        id: string;
        title: string;
        /** Bootstrap icon name, without the "bi-" prefix. */
        icon: string;
        grade?: string;
        score?: number;
        /** No result could be graded: shown as N/A rather than as the placeholder score. */
        unavailable?: boolean;
        /** What the folded header says about the section's checks. */
        status?: SectionStatus;
        /**
         * Whether the section starts unfolded. A section with nothing to change starts
         * folded, so the report reads as the list of what needs attention.
         */
        open?: boolean;
        /** Replaces the score and grade on the right of the header. */
        aside?: Snippet;
        children: Snippet;
        class?: string;
    }

    let {
        id,
        title,
        icon,
        grade,
        score,
        unavailable = false,
        status,
        open = true,
        aside,
        children,
        class: className = "",
    }: Props = $props();
</script>

<details class="card report-section {className}" {id} {open}>
    <summary
        class="card-header d-flex flex-wrap align-items-center gap-3 py-3 px-4 user-select-none"
    >
        <h4 class="mb-0 flex-grow-1 d-flex align-items-center gap-2">
            <i class="bi bi-{icon}" aria-hidden="true"></i>
            {title}
        </h4>
        {#if status}
            <span
                class={[
                    "badge rounded-pill border",
                    status.tone === "muted"
                        ? "text-body-secondary bg-body-secondary"
                        : `text-${status.tone}-emphasis bg-${status.tone}-subtle border-${status.tone}-subtle`,
                ]}>{status.label}</span
            >
        {/if}
        <span class="d-inline-flex align-items-center gap-2">
            {#if aside}
                {@render aside()}
            {:else if unavailable}
                <GradeDisplay grade="N/A" size="small" />
            {:else}
                {#if score !== undefined}
                    <span class="badge bg-{getScoreColorClass(score)}">{score}%</span>
                {/if}
                {#if grade}
                    <GradeDisplay {grade} size="small" />
                {/if}
            {/if}
            <i class="bi bi-chevron-down disclosure" aria-hidden="true"></i>
        </span>
    </summary>
    {@render children()}
</details>
