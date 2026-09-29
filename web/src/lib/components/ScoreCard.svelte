<script lang="ts">
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
    import ScoreLink from "./ScoreLink.svelte";

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

        {#if summary}
            <div class="row g-3 text-start">
                <div class="col-sm-6 col-md-4 col-lg">
                    <ScoreLink
                        href="#dns-details"
                        label="DNS"
                        grade={summary.dns_grade}
                        score={summary.dns_score}
                    />
                </div>
                <div class="col-sm-6 col-md-4 col-lg">
                    <ScoreLink
                        href="#authentication-details"
                        label="Authentication"
                        grade={summary.authentication_grade}
                        score={summary.authentication_score}
                        unavailable={authenticationUnavailable}
                        tooltipTitle={noAuthResultsTitle(source)}
                    />
                </div>
                <div class="col-sm-6 col-md-4 col-lg">
                    <ScoreLink
                        href="#rbl-details"
                        label="Blacklists"
                        grade={summary.blacklist_grade}
                        score={summary.blacklist_score}
                        unavailable={blacklistUnavailable}
                        tooltipTitle={noBlacklistResultsTitle()}
                    />
                </div>
                <div class="col-sm-6 col-md-4 col-lg">
                    <ScoreLink
                        href="#header-details"
                        label="Headers"
                        grade={summary.header_grade}
                        score={summary.header_score}
                    />
                </div>
                <div class="col-sm-6 col-md-4 col-lg">
                    <ScoreLink
                        href="#spam-details"
                        label="Spam Score"
                        grade={summary.spam_grade}
                        score={summary.spam_score}
                        unavailable={spamUnavailable}
                        tooltipTitle={noSpamResultsTitle()}
                    />
                </div>
                <div class="col-sm-6 col-md-4 col-lg">
                    <ScoreLink
                        href="#content-details"
                        label="Content"
                        grade={summary.content_grade}
                        score={summary.content_score}
                    />
                </div>
                {#if summary.attachments_grade}
                    <div class="col-sm-6 col-md-4 col-lg">
                        <ScoreLink
                            href="#attachment-details"
                            label="Attachments"
                            grade={summary.attachments_grade}
                            score={summary.attachments_score}
                        />
                    </div>
                {/if}
            </div>
        {/if}
    </div>
</div>

