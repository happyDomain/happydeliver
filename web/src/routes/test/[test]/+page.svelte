<script lang="ts">
    import { onMount, onDestroy } from "svelte";
    import { page } from "$app/state";
    import { getTest, getReport } from "$lib/api";
    import type { Test, Report } from "$lib/api/types.gen";
    import { ScoreCard, CheckCard, SpamAssassinCard, PendingState } from "$lib/components";

    let testId = $derived(page.params.test);
    let test = $state<Test | null>(null);
    let report = $state<Report | null>(null);
    let loading = $state(true);
    let error = $state<string | null>(null);
    let pollInterval: ReturnType<typeof setInterval> | null = null;
    let nextfetch = $state(23);
    let nbfetch = $state(0);

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
                    {#each report.checks as check}
                        <CheckCard {check} />
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

            <!-- Test Again Button -->
            <div class="row">
                <div class="col-12 text-center">
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
</style>
