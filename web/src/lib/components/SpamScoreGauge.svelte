<script lang="ts" module>
    /** A score from which the filter does something to the message. */
    export interface GaugeStep {
        at: number;
        /** What the filter does from there: Greylist, Reject. */
        label: string;
        /** What the message is past it, written on the gauge: Greylisted, Rejected. */
        zone: string;
    }
</script>

<script lang="ts">
    interface Props {
        score: number;
        /** In increasing order; the last one is where the message is treated as spam. */
        steps: GaugeStep[];
        /** What the message is below the first step. */
        base: string;
        /** Names the gauge for a screen reader, which cannot see the bar. */
        label: string;
        /** The verdict's colour: the bar is the only thing coloured on the gauge. */
        tone: "success" | "warning" | "danger";
    }

    let { score, steps, base, label, tone }: Props = $props();

    // Wide enough to show the last step with room past it, and the score wherever it falls:
    // a message far beyond the threshold, or far below zero, still has its needle on the bar.
    const top = $derived(steps.length > 0 ? steps[steps.length - 1].at : 5);
    const lo = $derived(Math.min(0, score));
    const hi = $derived(Math.max(top * 1.25, score + top * 0.05));
    const pos = (value: number) => ((value - lo) / (hi - lo)) * 100;

    // Each stretch of the scale, named for what the message is in it: read on the gauge,
    // where the score falls, rather than in a legend beside it. The first starts at zero
    // rather than at a negative score, so its name stays clear of the 0 under the bar.
    const zones = $derived(
        [{ at: 0, zone: base }, ...steps].map((step, i, all) => ({
            name: step.zone,
            from: step.at,
            to: all[i + 1]?.at ?? hi,
        })),
    );
    const current = $derived(zones.findLast((z) => score >= z.from) ?? zones[0]);

    // The bar fills from zero to the score, on whichever side of zero it is.
    const fillFrom = $derived(pos(Math.min(0, score)));
    const fillTo = $derived(pos(Math.max(0, score)));
</script>

<div
    class="gauge"
    role="meter"
    aria-label={label}
    aria-valuenow={score}
    aria-valuemin={lo}
    aria-valuemax={hi}
>
    <div class="track">
        <span
            class="fill bg-{tone}"
            style:left="{fillFrom}%"
            style:width="{Math.max(fillTo - fillFrom, 0.75)}%"
        ></span>
        {#if lo < 0}
            <span class="zero" style:left="{pos(0)}%"></span>
        {/if}
        {#each steps as step (step.at)}
            <span class="tick" style:left="{pos(step.at)}%" title="{step.label} from {step.at}"
            ></span>
        {/each}
    </div>
    <div class="scale small">
        {#each zones as zone (zone.from)}
            <span
                class={["zone", zone === current && `current text-${tone}-emphasis`]}
                style:left="{pos(zone.from)}%"
                style:width="{pos(zone.to) - pos(zone.from)}%"
                title="{zone.name}{zone === zones[0] ? '' : ` from ${zone.from}`}">{zone.name}</span
            >
        {/each}
        {#if lo < 0}
            <span class="value" style:left="{pos(0)}%">0</span>
        {/if}
        {#each steps as step (step.at)}
            <span class="value" style:left="{pos(step.at)}%" title="{step.label} from {step.at}"
                >{step.at}</span
            >
        {/each}
    </div>
</div>

<style>
    .gauge {
        margin: 0.25rem 0 0.75rem;
    }

    .track {
        position: relative;
        height: 0.625rem;
        border-radius: 999px;
        background: color-mix(in srgb, var(--bs-body-color) 10%, transparent);
        overflow: hidden;
    }

    .fill,
    .zero,
    .tick {
        position: absolute;
        top: 0;
        bottom: 0;
    }

    .fill {
        border-radius: 999px;
    }

    .zero,
    .tick {
        width: 2px;
        margin-left: -1px;
        background: var(--bs-body-color);
        opacity: 0.35;
    }

    /* Under the bar: the thresholds on their ticks, and between them what the message is. */
    .scale {
        position: relative;
        height: 1.25rem;
        margin-top: 0.125rem;
        color: var(--hd-fg-3);
        font-variant-numeric: tabular-nums;

        span {
            position: absolute;
            top: 0;
            white-space: nowrap;
        }

        .value {
            transform: translateX(-50%);
        }

        /* Clear of the numbers at either end; cut short where the stretch is too narrow. */
        .zone {
            padding: 0 1.5em;
            text-align: center;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .current {
            font-weight: 600;
        }
    }
</style>
