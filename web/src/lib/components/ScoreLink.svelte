<script lang="ts">
    import type { Tooltip } from "bootstrap";

    import type { SectionStatus } from "#lib/sections.js";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        href: string;
        label: string;
        grade?: string;
        score?: number;
        unavailable?: boolean;
        tooltipTitle?: string;
        /** What the section has to change, under its name. */
        status?: SectionStatus;
    }

    let { href, label, grade, score, unavailable, tooltipTitle, status }: Props = $props();

    const statusClass: Record<SectionStatus["tone"], string> = {
        success: "text-success",
        info: "text-info",
        warning: "text-warning",
        danger: "text-danger",
        muted: "text-muted",
    };

    interface TooltipParams {
        enabled: boolean;
        title: string;
    }

    function unavailableTooltip(node: HTMLElement, params: TooltipParams) {
        let instance: Tooltip | undefined;
        let destroyed = false;

        async function sync({ enabled, title }: TooltipParams) {
            instance?.dispose();
            instance = undefined;

            if (enabled) {
                const { Tooltip } = await import("bootstrap");
                if (destroyed) return;
                instance = new Tooltip(node, {
                    title,
                    trigger: "click hover focus",
                    customClass: "score-tooltip",
                });
            }
        }

        sync(params);

        return {
            update: sync,
            destroy: () => {
                destroyed = true;
                instance?.dispose();
            },
        };
    }
</script>

<!-- eslint-disable svelte/no-navigation-without-resolve -- the caller passes an already resolved route -->
<a
    {href}
    class="text-decoration-none"
    onclick={(e) => {
        if (unavailable) e.preventDefault();
    }}
    use:unavailableTooltip={{ enabled: !!unavailable, title: tooltipTitle ?? "" }}
>
    <div class="p-2 rounded text-center summary-card bg-light">
        {#if unavailable}
            <GradeDisplay grade="N/A" />
        {:else}
            <GradeDisplay {grade} {score} />
        {/if}
        <small class="text-muted d-block">{label}</small>
        {#if status && !unavailable}
            <small class="d-block fw-semibold {statusClass[status.tone]}">
                {status.label === "All checks passed" ? "All passed" : status.label}
            </small>
        {/if}
    </div>
</a>

<!-- eslint-enable svelte/no-navigation-without-resolve -->

<style>
    .summary-card {
        border: 1px solid transparent;
        transition:
            background-color 0.2s ease-in-out,
            border-color 0.2s ease-in-out;
        cursor: pointer;
    }

    .summary-card:hover {
        background-color: var(--hd-secondary-hover) !important;
        border-color: var(--hd-border-3);
    }

    :global(.score-tooltip .tooltip-inner) {
        max-width: 16rem;
        text-align: left;
    }
</style>
