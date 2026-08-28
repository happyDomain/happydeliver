<script lang="ts">
    import type { Tooltip } from "bootstrap";
    import type { AuthenticationResults, Report, ScoreSummary } from "$lib/api/types.gen";
    import {
        hasNoAuthenticationResults,
        noAuthResultsTitle,
        type MessageSource,
    } from "$lib/authentication";
    import { hasNoBlacklistResults, noBlacklistResultsTitle } from "$lib/blacklist";
    import { hasNoSpamResults, noSpamResultsTitle } from "$lib/spam";
    import { theme } from "$lib/stores/theme";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        grade: string;
        score: number;
        reanalyzing?: boolean;
        summary?: ScoreSummary;
        authentication?: AuthenticationResults;
        source?: MessageSource;
        spamFilters?: Pick<Report, "spamassassin" | "rspamd">;
        blacklists?: Pick<Report, "blacklists">;
    }

    let {
        grade,
        score,
        reanalyzing,
        summary,
        authentication,
        source,
        spamFilters,
        blacklists,
    }: Props = $props();

    // Without an Authentication-Results header there is nothing to grade: the computed F
    // reflects the configuration of whichever server was supposed to produce it, not the
    // sender's.
    let authenticationUnavailable = $derived(hasNoAuthenticationResults(authentication));

    // Some receivers (Gmail, for instance) never run SpamAssassin/rspamd directly, so there is
    // nothing to grade either.
    let spamUnavailable = $derived(hasNoSpamResults(spamFilters));

    // No IP could be extracted from the message to check against DNS blacklists.
    let blacklistUnavailable = $derived(hasNoBlacklistResults(blacklists));

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
</script>

<div class="card shadow-lg {$theme === 'light' ? 'bg-white' : 'bg-dark'}">
    <div class="card-body p-5 text-center">
        <div class="mb-3">
            {#if reanalyzing}
                <div class="spinner-border spinner-border-lg text-muted display-1"></div>
            {:else}
                <GradeDisplay {grade} {score} size="large" />
            {/if}
        </div>
        <h3 class="fw-bold mb-2">
            {#if reanalyzing}
                Analyzing in progress&hellip;
            {:else}
                {getScoreLabel(grade)}
            {/if}
        </h3>
        <p class="text-muted mb-4">Overall Deliverability Score</p>

        {#snippet scoreLink(
            href: string,
            label: string,
            grade: string | undefined,
            score: number | undefined,
            unavailable?: boolean,
            tooltipTitle?: string,
        )}
            <div class="col-sm-6 col-md-4 col-lg">
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
            </div>
        {/snippet}

        {#if summary}
            <div class="row g-3 text-start">
                {@render scoreLink("#dns-details", "DNS", summary.dns_grade, summary.dns_score)}
                {@render scoreLink(
                    "#authentication-details",
                    "Authentication",
                    summary.authentication_grade,
                    summary.authentication_score,
                    authenticationUnavailable,
                    noAuthResultsTitle(source),
                )}
                {@render scoreLink(
                    "#rbl-details",
                    "Blacklists",
                    summary.blacklist_grade,
                    summary.blacklist_score,
                    blacklistUnavailable,
                    noBlacklistResultsTitle(),
                )}
                {@render scoreLink(
                    "#header-details",
                    "Headers",
                    summary.header_grade,
                    summary.header_score,
                )}
                {@render scoreLink(
                    "#spam-details",
                    "Spam Score",
                    summary.spam_grade,
                    summary.spam_score,
                    spamUnavailable,
                    noSpamResultsTitle(),
                )}
                {@render scoreLink(
                    "#content-details",
                    "Content",
                    summary.content_grade,
                    summary.content_score,
                )}
            </div>
        {/if}
    </div>
</div>

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
