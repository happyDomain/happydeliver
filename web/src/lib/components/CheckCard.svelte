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
    import { getContext, type Snippet } from "svelte";
    import type { ClassValue } from "svelte/elements";

    import type { Issue } from "#lib/api/types.gen.js";
    import { issueDocLinks, type DocLink } from "#lib/docs.js";
    import { compareBySeverity, type Severity } from "#lib/issues.js";
    import { checkListKey } from "./CheckList.svelte";
    import DocLinks from "./DocLinks.svelte";
    import IssueNote from "./IssueNote.svelte";

    interface Props {
        id?: string;
        title: string;
        /**
         * How the check came out. When issues are given, they decide instead: this only
         * says whether a check with nothing to report is graded at all.
         */
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
        /**
         * What the analyser found to change about this check, shown first when unfolded.
         * Given, they are the only source of the status, so an icon that warns always comes
         * with what it warns about.
         */
        issues?: Issue[];
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
        issues,
        open,
        class: className = "mb-3",
        children,
    }: Props = $props();

    // In a CheckList, a row among others; on its own, a card.
    const row = getContext<boolean>(checkListKey) ?? false;

    const severityStatus: Record<Severity, CheckStatus> = {
        critical: "fail",
        high: "fail",
        medium: "warn",
        low: "improve",
        info: "info",
    };

    const sorted = $derived(issues ? [...issues].sort(compareBySeverity) : []);

    const shownStatus = $derived.by<CheckStatus>(() => {
        if (issues === undefined) return status;
        if (sorted.length > 0) return severityStatus[sorted[0].severity];
        return status === "neutral" || status === "info" ? status : "pass";
    });

    // The check's own references, then those of its issues, each once.
    const allDocs = $derived(
        [...(docs ?? []), ...sorted.flatMap((issue) => issueDocLinks(issue.type))].filter(
            (d, i, all) => all.findIndex((other) => other.url === d.url) === i,
        ),
    );

    const startOpen = $derived(open ?? (shownStatus === "fail" || shownStatus === "warn"));
</script>

<details
    class={row ? "check-card check-row" : ["card check-card", className]}
    {id}
    open={startOpen}
>
    <summary
        class={[
            "d-flex align-items-center gap-3 py-2 user-select-none",
            row ? "px-1" : "card-header px-3",
        ]}
    >
        <i
            class="bi {icon ?? icons[shownStatus]} fs-5 flex-shrink-0"
            role="img"
            aria-label={labels[shownStatus]}
            title={labels[shownStatus]}
        ></i>
        <span
            class="flex-grow-1 overflow-hidden d-flex flex-wrap align-items-baseline column-gap-3"
        >
            <h5 class={row ? "fs-6 fw-semibold mb-0" : "mb-0"}>{title}</h5>
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
            <span class={row ? "small text-body-secondary" : "badge bg-secondary"}>{tag}</span>
        {/if}
        <i class="bi bi-chevron-down disclosure" aria-hidden="true"></i>
    </summary>
    {#if sorted.length > 0}
        <div class={row ? "check-findings" : "check-findings card-body pb-0"}>
            {#each sorted as issue, i (i)}
                <IssueNote {issue} />
            {/each}
        </div>
    {/if}
    {@render children?.()}
    {#if allDocs.length > 0}
        <div class={row ? "check-docs" : "card-footer"}>
            <DocLinks docs={allDocs} />
        </div>
    {/if}
</details>
