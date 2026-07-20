<script lang="ts">
    import type { Report, ScoreSummary } from "$lib/api/types.gen";
    import { theme } from "$lib/stores/theme";
    import GradeDisplay from "./GradeDisplay.svelte";
    import { Gauge, MiniDonut } from "$lib/components";

    interface Props {
        grade: string;
        score: number;
        reanalyzing?: boolean;
        report: Report;
        summary?: ScoreSummary;
    }

    let { grade, score, reanalyzing, report, summary }: Props = $props();

    function getScoreLabel(grade: string): string {
        switch (grade) {
            case "A+":
                return "Excellent Deliverability";
            case "A":
                return "Good Deliverability";
            case "B":
                return "Fair Deliverability";
            case "C":
                return "Moderate Issues";
            case "D":
                return "Poor Deliverability";
            case "E":
                return "Critical Issues";
            case "F":
                return "Severe Problems";
            default:
                return "Unknown Status";
        }
    }

    const sectionScores = $derived([
        {
            label: "DNS",
            grade: summary?.dns_grade,
            pct: summary?.dns_score,
        },
        {
            label: "Authentication",
            grade: summary?.authentication_grade,
            pct: summary?.authentication_score,
        },
        {
            label: "Blacklist",
            grade: summary?.blacklist_grade,
            pct: summary?.blacklist_score,
        },
        {
            label: "Headers",
            grade: summary?.header_grade,
            pct: summary?.header_score,
        },
        {
            label: "Spam Score",
            grade: summary?.spam_grade,
            pct: summary?.spam_score,
        },
        {
            label: "Content",
            grade: summary?.content_grade,
            pct: summary?.content_score,
        },
    ]);
</script>

<div class="hero">
    <div class="hero-bg"></div>
    <div class="hero-row">
        <div>
            <div class="eyebrow">
                <span>Deliverability report</span><span class="sep"></span><span>{report.id}</span
                ><span class="sep"></span><span
                    >{Intl.DateTimeFormat("default", {
                        dateStyle: "long",
                        timeStyle: "short",
                    }).format(new Date(report.created_at))}</span
                >
            </div>
            <h1 class="big">
                {#if reanalyzing}
                    Analyzing in progress&hellip;
                {:else}
                    {getScoreLabel(grade)}
                {/if}
            </h1>
            <!--p class="note">
                Authentication is mostly in order, but blacklist hits and a noisy content score will
                hurt inbox placement.
            </p-->
        </div>
        {#if reanalyzing}
            <div class="spinner-border spinner-border-lg text-muted display-1"></div>
        {:else}
            <Gauge pct={report.score} grade={report.grade} size={210} />
        {/if}
    </div>
</div>
<div class="strip">
    {#each sectionScores as s}
        <div class="cell">
            <div class="cell-top">
                <MiniDonut pct={s.pct} grade={s.grade} /><span class="pct">{s.pct}%</span>
            </div>
            <div class="cell-label">{s.label}</div>
        </div>
    {/each}
</div>

<style>
    .hero {
        background: var(--hd-brand-dark);
        color: var(--hd-brand-dark-fg);
        padding: 48px 56px 56px;
        position: relative;
        overflow: hidden;
    }
    .hero-bg {
        position: absolute;
        inset: 0;
        opacity: 0.06;
        background-image: repeating-linear-gradient(
            90deg,
            transparent 0,
            transparent 39px,
            var(--hd-brand-dark-muted) 39px,
            var(--hd-brand-dark-muted) 40px
        );
        pointer-events: none;
    }
    .hero-row {
        display: grid;
        grid-template-columns: 1fr auto;
        gap: 56px;
        align-items: center;
        position: relative;
    }
    .eyebrow {
        font-family: var(--hd-font-mono);
        font-size: 11px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: var(--hd-brand-dark-muted);
        margin-bottom: 16px;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .sep {
        width: 3px;
        height: 3px;
        border-radius: 50%;
        background: var(--hd-brand-dark-muted);
    }
    .big {
        font-family: var(--hd-font-brand);
        font-weight: 600;
        font-size: 56px;
        line-height: 1.02;
        letter-spacing: -0.025em;
        margin: 0;
        color: var(--hd-brand-dark-fg);
    }
    .note {
        margin: 18px 0 0;
        max-width: 580px;
        font-size: 16px;
        color: var(--hd-brand-dark-muted);
        line-height: 1.55;
    }
    .meta {
        display: flex;
        gap: 28px;
        margin-top: 24px;
        flex-wrap: wrap;
    }
    .meta-item {
        display: flex;
        flex-direction: column;
        gap: 4px;
    }
    .meta-label {
        font-family: var(--hd-font-mono);
        font-size: 10px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--hd-brand-dark-muted);
    }
    .meta-val {
        font-family: var(--hd-font-mono);
        font-size: 13px;
        color: var(--hd-brand-dark-fg);
        font-weight: 500;
    }
    .strip {
        background: var(--hd-bg-canvas);
        border: 1px solid var(--hd-border-1);
        border-radius: var(--hd-radius-lg);
        margin: -40px 56px 0;
        padding: 8px;
        display: grid;
        grid-template-columns: repeat(7, 1fr);
        gap: 4px;
        position: relative;
        z-index: 2;
    }
    .cell {
        padding: 14px 12px;
        border-radius: var(--hd-radius-md);
        display: flex;
        flex-direction: column;
        gap: 10px;
        cursor: default;
    }
    .cell-top {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
    }
    .pct {
        font-family: var(--hd-font-mono);
        font-size: 11px;
        color: var(--hd-fg-4);
    }
    .cell-label {
        font-size: 13px;
        font-weight: 600;
        color: var(--hd-fg-1);
    }
</style>
