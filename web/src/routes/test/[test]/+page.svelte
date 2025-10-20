<script lang="ts">
    import { onMount, onDestroy } from "svelte";
    import { page } from "$app/state";
    import { getTest, getReport, reanalyzeReport } from "$lib/api";
    import type { Test, Report } from "$lib/api/types.gen";
    import { ScoreCard, CheckCard, SpamAssassinCard, PendingState } from "$lib/components";

    let testId = $derived(page.params.test);
    let test = $state<Test | null>(null);
    let report = $state<Report | null>(null);
    let loading = $state(true);
    let error = $state<string | null>(null);
    let reanalyzing = $state(false);
    let pollInterval: ReturnType<typeof setInterval> | null = null;
    let nextfetch = $state(23);
    let nbfetch = $state(0);

    // Group checks by category
    let groupedChecks = $derived(() => {
        if (!report) return {};

        const groups: Record<string, typeof report.checks> = {};
        for (const check of report.checks) {
            if (!groups[check.category]) {
                groups[check.category] = [];
            }
            groups[check.category].push(check);
        }
        return groups;
    });

    async function fetchTest() {
        if (nbfetch > 0) {
            nextfetch = Math.max(nextfetch, Math.floor(3 + nbfetch * 0.5));
        }
        nbfetch += 1;

        try {
            const testResponse = await getTest({ path: { id: testId } });
            if (testResponse.data) {
                test = testResponse.data;

                if (test.status === "analyzed") {
                    const reportResponse = await getReport({ path: { id: testId } });
                    if (reportResponse.data) {
                        report = reportResponse.data;
                    }
                    stopPolling();
                }
            }
            loading = false;
        } catch (err) {
            error = err instanceof Error ? err.message : "Failed to fetch test";
            loading = false;
            stopPolling();
        }
    }

    function startPolling() {
        pollInterval = setInterval(() => {
            nextfetch -= 1;

            if (nextfetch <= 0) {
                if (!document.hidden) {
                    fetchTest();
                } else {
                    nextfetch = 1;
                }
            }
        }, 1000);
    }

    function stopPolling() {
        if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
        }
    }

    onMount(() => {
        fetchTest();
        startPolling();
    });

    onDestroy(() => {
        stopPolling();
    });

    function getCategoryIcon(category: string): string {
        switch (category) {
            case "authentication":
                return "bi-shield-check";
            case "dns":
                return "bi-diagram-3";
            case "content":
                return "bi-file-text";
            case "blacklist":
                return "bi-shield-exclamation";
            case "headers":
                return "bi-list-ul";
            case "spam":
                return "bi-filter";
            default:
                return "bi-question-circle";
        }
    }

    function getCategoryScore(checks: typeof report.checks): number {
        return checks.reduce((sum, check) => sum + check.score, 0);
    }

    function getCategoryMaxScore(category: string): number {
        switch (category) {
            case "authentication":
                return 3;
            case "spam":
                return 2;
            case "blacklist":
                return 2;
            case "content":
                return 2;
            case "headers":
                return 1;
            case "dns":
                return 0; // DNS checks contribute to other categories
            default:
                return 0;
        }
    }

    function getScoreColorClass(score: number, maxScore: number): string {
        if (maxScore === 0) return "text-muted";
        const percentage = (score / maxScore) * 100;
        if (percentage >= 80) return "text-success";
        if (percentage >= 50) return "text-warning";
        return "text-danger";
    }

    async function handleReanalyze() {
        if (!testId || reanalyzing) return;

        reanalyzing = true;
        error = null;

        try {
            const response = await reanalyzeReport({ path: { id: testId } });
            if (response.data) {
                report = response.data;
            }
        } catch (err) {
            error = err instanceof Error ? err.message : "Failed to reanalyze report";
        } finally {
            reanalyzing = false;
        }
    }
</script>

<svelte:head>
    <title>{test ? `Test ${test.id.slice(0, 7)} - happyDeliver` : "Loading..."}</title>
</svelte:head>

<div class="container py-5">
    {#if loading}
        <div class="text-center py-5">
            <div
                class="spinner-border text-primary"
                role="status"
                style="width: 3rem; height: 3rem;"
            >
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-3 text-muted">Loading test...</p>
        </div>
    {:else if error}
        <div class="row justify-content-center">
            <div class="col-lg-6">
                <div class="alert alert-danger" role="alert">
                    <i class="bi bi-exclamation-triangle me-2"></i>
                    {error}
                </div>
            </div>
        </div>
    {:else if test && test.status !== "analyzed"}
        <!-- Pending State -->
        <PendingState {nextfetch} {nbfetch} {test} on:force-inbox-check={() => fetchTest()} />
    {:else if report}
        <!-- Results State -->
        <div class="fade-in">
            <!-- Score Header -->
            <div class="row mb-4">
                <div class="col-12">
                    <ScoreCard score={report.score} summary={report.summary} />
                </div>
            </div>

            <!-- Detailed Checks -->
            <div class="row mb-4">
                <div class="col-12">
                    <h3 class="fw-bold mb-3">Detailed Checks</h3>
                    {#each Object.entries(groupedChecks()) as [category, checks]}
                        {@const categoryScore = getCategoryScore(checks)}
                        {@const maxScore = getCategoryMaxScore(category)}
                        <div class="category-section mb-4">
                            <h4 class="category-title text-capitalize mb-3 d-flex justify-content-between align-items-center">
                                <span>
                                    <i class="bi {getCategoryIcon(category)} me-2"></i>
                                    {category}
                                </span>
                                <span class="category-score {getScoreColorClass(categoryScore, maxScore)}">
                                    {categoryScore.toFixed(1)}{#if maxScore > 0} / {maxScore}{/if} pts
                                </span>
                            </h4>
                            {#each checks as check}
                                <CheckCard {check} />
                            {/each}
                        </div>
                    {/each}
                </div>
            </div>

            <!-- Additional Information -->
            {#if report.spamassassin}
                <div class="row mb-4">
                    <div class="col-12">
                        <SpamAssassinCard spamassassin={report.spamassassin} />
                    </div>
                </div>
            {/if}

            <!-- Action Buttons -->
            <div class="row">
                <div class="col-12 text-center">
                    <button
                        class="btn btn-outline-secondary btn-lg me-3"
                        onclick={handleReanalyze}
                        disabled={reanalyzing}
                    >
                        {#if reanalyzing}
                            <span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                            Reanalyzing...
                        {:else}
                            <i class="bi bi-arrow-clockwise me-2"></i>
                            Reanalyze with Latest Version
                        {/if}
                    </button>
                    <a href="/test/" class="btn btn-primary btn-lg">
                        <i class="bi bi-arrow-repeat me-2"></i>
                        Test Another Email
                    </a>
                </div>
            </div>
        </div>
    {/if}
</div>

<style>
    .fade-in {
        animation: fadeIn 0.6s ease-out;
    }

    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(20px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    .category-section {
        margin-bottom: 2rem;
    }

    .category-title {
        font-size: 1.25rem;
        font-weight: 600;
        color: #495057;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #e9ecef;
    }

    .category-score {
        font-size: 1rem;
        font-weight: 700;
    }
</style>
