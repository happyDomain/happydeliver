<script lang="ts">
    import { onMount, onDestroy } from "svelte";
    import { page } from "$app/state";
    import { getTest, getReport, reanalyzeReport } from "$lib/api";
    import type { Test, Report } from "$lib/api/types.gen";
    import {
        ScoreCard,
        SummaryCard,
        SpamAssassinCard,
        PendingState,
        AuthenticationCard,
        DnsRecordsCard,
        BlacklistCard,
        ContentAnalysisCard,
        HeaderAnalysisCard
    } from "$lib/components";

    let testId = $derived(page.params.test);
    let test = $state<Test | null>(null);
    let report = $state<Report | null>(null);
    let loading = $state(true);
    let error = $state<string | null>(null);
    let reanalyzing = $state(false);
    let pollInterval: ReturnType<typeof setInterval> | null = null;
    let nextfetch = $state(23);
    let nbfetch = $state(0);
    let menuOpen = $state(false);

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

    async function handleReanalyze() {
        if (!testId || reanalyzing) return;

        menuOpen = false;
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

    function handleExportJSON() {
        const dataStr = JSON.stringify(report, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `report-${testId}.json`;
        link.click();
        URL.revokeObjectURL(url);
        menuOpen = false;
    }
</script>

<svelte:head>
    <title>{report ? `Test of ${report.dns_results.from_domain} ${report.test_id.slice(0, 7)}` : (test ? `Test ${test.id.slice(0, 7)}` : "Loading...")} - happyDeliver</title>
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
            <div class="row mb-4" id="score">
                <div class="col-12">
                    <div class="position-relative">
                        <div class="position-absolute py-2 px-3" style="z-index: 2; right: 0">
                            <div class="menu-container">
                                <button
                                    class="btn btn-outline-secondary"
                                    type="button"
                                    onclick={() => (menuOpen = !menuOpen)}
                                    aria-label="Menu"
                                >
                                    <i class="bi bi-three-dots-vertical"></i>
                                </button>
                                {#if menuOpen}
                                    <div class="menu-dropdown">
                                        <button class="menu-item" onclick={handleExportJSON}>
                                            <i class="bi bi-download me-2"></i>
                                            Export JSON Report
                                        </button>
                                        <button
                                            class="menu-item"
                                            onclick={handleReanalyze}
                                            disabled={reanalyzing}
                                        >
                                            <i class="bi bi-arrow-clockwise me-2"></i>
                                            Reanalyze with Latest Version
                                        </button>
                                        <hr class="menu-divider" />
                                        <a
                                            class="menu-item"
                                            href={`/api/report/${testId}/raw`}
                                            target="_blank"
                                            onclick={() => (menuOpen = false)}
                                        >
                                            <i class="bi bi-file-earmark-text me-2"></i>
                                            View Raw Email
                                        </a>
                                    </div>
                                {/if}
                            </div>
                        </div>
                    </div>
                    <ScoreCard grade={report.grade} score={report.score} summary={report.summary} {reanalyzing} />
                </div>
            </div>

            <!-- Summary -->
            <div class="row mb-4">
                <div class="col-12">
                    <SummaryCard {report} />
                </div>
            </div>

            <!-- DNS Records -->
            {#if report.dns_results}
                <div class="row mb-4" id="dns">
                    <div class="col-12">
                        <DnsRecordsCard
                            domainAlignment={report.header_analysis?.domain_alignment}
                            dnsResults={report.dns_results}
                            dnsGrade={report.summary?.dns_grade}
                            dnsScore={report.summary?.dns_score}
                            receivedChain={report.header_analysis?.received_chain}
                        />
                    </div>
                </div>
            {/if}

            <!-- Authentication Results -->
            {#if report.authentication}
                <div class="row mb-4" id="authentication">
                    <div class="col-12">
                        <AuthenticationCard
                            authentication={report.authentication}
                            authenticationGrade={report.summary?.authentication_grade}
                            authenticationScore={report.summary?.authentication_score}
                            dnsResults={report.dns_results}
                        />
                    </div>
                </div>
            {/if}

            <!-- Blacklist Checks -->
            {#if report.blacklists && Object.keys(report.blacklists).length > 0}
                <div class="row mb-4" id="blacklist">
                    <div class="col-12">
                        <BlacklistCard
                            blacklists={report.blacklists}
                            blacklistGrade={report.summary?.blacklist_grade}
                            blacklistScore={report.summary?.blacklist_score}
                            receivedChain={report.header_analysis?.received_chain}
                        />
                    </div>
                </div>
            {/if}

            <!-- Header Analysis -->
            {#if report.header_analysis}
                <div class="row mb-4" id="header">
                    <div class="col-12">
                        <HeaderAnalysisCard
                            dmarcRecord={report.dns_results.dmarc_record}
                            headerAnalysis={report.header_analysis}
                            headerGrade={report.summary?.header_grade}
                            headerScore={report.summary?.header_score}
                            xAlignedFrom={report.authentication.x_aligned_from}
                        />
                    </div>
                </div>
            {/if}

            <!-- Additional Information -->
            {#if report.spamassassin}
                <div class="row mb-4" id="spam">
                    <div class="col-12">
                        <SpamAssassinCard
                            spamassassin={report.spamassassin}
                            spamGrade={report.summary?.spam_grade}
                            spamScore={report.summary?.spam_score}
                        />
                    </div>
                </div>
            {/if}

            <!-- Content Analysis -->
            {#if report.content_analysis}
                <div class="row mb-4" id="content">
                    <div class="col-12">
                        <ContentAnalysisCard
                            contentAnalysis={report.content_analysis}
                            contentGrade={report.summary?.content_grade}
                            contentScore={report.summary?.content_score}
                        />
                    </div>
                </div>
            {/if}

            <!-- Action Buttons -->
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

    .menu-container {
        position: relative;
    }

    .menu-dropdown {
        position: absolute;
        top: 100%;
        right: 0;
        margin-top: 0.25rem;
        background: white;
        border: 1px solid #dee2e6;
        border-radius: 0.375rem;
        box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
        min-width: 250px;
        z-index: 1000;
        padding: 0.5rem 0;
    }

    .menu-item {
        display: block;
        width: 100%;
        padding: 0.5rem 1rem;
        background: none;
        border: none;
        text-align: left;
        color: #212529;
        text-decoration: none;
        cursor: pointer;
        transition: background-color 0.15s ease-in-out;
        font-size: 1rem;
    }

    .menu-item:hover:not(:disabled) {
        background-color: #f8f9fa;
    }

    .menu-item:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }

    .menu-divider {
        margin: 0.5rem 0;
        border: 0;
        border-top: 1px solid #dee2e6;
    }
</style>
