<script lang="ts">
    import type { Tooltip } from "bootstrap";
    import { theme } from "$lib/stores/theme";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        href: string;
        label: string;
        grade?: string;
        score?: number;
        unavailable?: boolean;
        tooltipTitle?: string;
    }

    let { href, label, grade, score, unavailable, tooltipTitle }: Props = $props();

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

<a
    {href}
    class="text-decoration-none"
    onclick={(e) => {
        if (unavailable) e.preventDefault();
    }}
    use:unavailableTooltip={{ enabled: !!unavailable, title: tooltipTitle ?? "" }}
>
    <div
        class="p-2 rounded text-center summary-card"
        class:bg-light={$theme === "light"}
        class:bg-secondary={$theme !== "light"}
    >
        {#if unavailable}
            <GradeDisplay grade="N/A" />
        {:else}
            <GradeDisplay {grade} {score} />
        {/if}
        <small class="text-muted d-block">{label}</small>
    </div>
</a>

<style>
    .summary-card {
        transition: all 0.2s ease-in-out;
        cursor: pointer;
    }

    .summary-card:hover {
        background-color: #e2e6ea !important;
        transform: translateY(-2px);
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    }

    :global([data-bs-theme="dark"]) .summary-card:hover {
        background-color: #495057 !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
    }

    :global(.score-tooltip .tooltip-inner) {
        max-width: 16rem;
        text-align: left;
    }
</style>
