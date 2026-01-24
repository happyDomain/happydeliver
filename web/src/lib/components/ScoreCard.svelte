<script lang="ts">
    import type { ScoreSummary } from "$lib/api/types.gen";
    import { theme } from "$lib/stores/theme";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        grade: string;
        score: number;
        reanalyzing?: boolean;
        summary?: ScoreSummary;
    }

    let { grade, score, reanalyzing, summary }: Props = $props();

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
                    <a href="#dns-details" class="text-decoration-none">
                        <div
                            class="p-2 rounded text-center summary-card"
                            class:bg-light={$theme === "light"}
                            class:bg-secondary={$theme !== "light"}
                        >
                            <GradeDisplay grade={summary.dns_grade} score={summary.dns_score} />
                            <small class="text-muted d-block">DNS</small>
                        </div>
                    </a>
                </div>
                <div class="col-sm-6 col-md-4 col-lg">
                    <a href="#authentication-details" class="text-decoration-none">
                        <div
                            class="p-2 rounded text-center summary-card"
                            class:bg-light={$theme === "light"}
                            class:bg-secondary={$theme !== "light"}
                        >
                            <GradeDisplay
                                grade={summary.authentication_grade}
                                score={summary.authentication_score}
                            />
                            <small class="text-muted d-block">Authentication</small>
                        </div>
                    </a>
                </div>
                <div class="col-sm-6 col-md-4 col-lg">
                    <a href="#rbl-details" class="text-decoration-none">
                        <div
                            class="p-2 rounded text-center summary-card"
                            class:bg-light={$theme === "light"}
                            class:bg-secondary={$theme !== "light"}
                        >
                            <GradeDisplay
                                grade={summary.blacklist_grade}
                                score={summary.blacklist_score}
                            />
                            <small class="text-muted d-block">Blacklists</small>
                        </div>
                    </a>
                </div>
                <div class="col-sm-6 col-md-4 col-lg">
                    <a href="#header-details" class="text-decoration-none">
                        <div
                            class="p-2 rounded text-center summary-card"
                            class:bg-light={$theme === "light"}
                            class:bg-secondary={$theme !== "light"}
                        >
                            <GradeDisplay
                                grade={summary.header_grade}
                                score={summary.header_score}
                            />
                            <small class="text-muted d-block">Headers</small>
                        </div>
                    </a>
                </div>
                <div class="col-sm-6 col-md-4 col-lg">
                    <a href="#spam-details" class="text-decoration-none">
                        <div
                            class="p-2 rounded text-center summary-card"
                            class:bg-light={$theme === "light"}
                            class:bg-secondary={$theme !== "light"}
                        >
                            <GradeDisplay grade={summary.spam_grade} score={summary.spam_score} />
                            <small class="text-muted d-block">Spam Score</small>
                        </div>
                    </a>
                </div>
                <div class="col-sm-6 col-md-4 col-lg">
                    <a href="#content-details" class="text-decoration-none">
                        <div
                            class="p-2 rounded text-center summary-card"
                            class:bg-light={$theme === "light"}
                            class:bg-secondary={$theme !== "light"}
                        >
                            <GradeDisplay
                                grade={summary.content_grade}
                                score={summary.content_score}
                            />
                            <small class="text-muted d-block">Content</small>
                        </div>
                    </a>
                </div>
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
</style>
