<script lang="ts">
    import { page } from "$app/state";
    import { resolve } from "$app/paths";
    import { onDestroy, onMount, tick } from "svelte";
    import TileLoader from "#lib/components/TileLoader.svelte";

    import { getReport, getTest, reanalyzeReport } from "#lib/api/index.js";
    import type { Report, Test } from "#lib/api/types.gen.js";
    import { adviceAnchorsBySymbol } from "#lib/issues.js";
    import { revealHash, revealOnNavigation } from "#lib/reveal.js";
    import { sectionStatuses, type SectionKey } from "#lib/sections.js";
    import {
        AuthenticationCard,
        BlacklistCard,
        AttachmentAnalysisCard,
        ContentAnalysisCard,
        DnsRecordsCard,
        DomainReputationCard,
        EmailPathCard,
        ErrorDisplay,
        HeaderAnalysisCard,
        PendingState,
        ReportSection,
        RspamdCard,
        ScoreCard,
        SpamAssassinCard,
        SummaryCard,
        TinySurvey,
        WhitelistCard,
    } from "#lib/components/index.js";
    import { apiMessage } from "#lib/errors.js";

    let testId = $derived(page.params.test);
    let test = $state<Test | null>(null);
    let report = $state<Report | null>(null);
    let loading = $state(true);
    let error = $state<string | null>(null);
    let errorStatus = $state<number>(500);
    let reanalyzing = $state(false);
    let pollInterval: ReturnType<typeof setInterval> | null = null;
    let reportRetryTimeout: ReturnType<typeof setTimeout> | null = null;
    let nextfetch = $state(23);
    let nbfetch = $state(0);
    let menuOpen = $state(false);
    let fetching = $state(false);
    let reportRateLimited = $state(false);

    // How each section reads once folded: a section with something to fix opens, one that
    // only passed stays a single line.
    const statuses = $derived(report ? sectionStatuses(report) : {});

    // A section with no status was not graded (attachments, when there are none): nothing
    // in it calls for attention.
    function opens(section: SectionKey): boolean {
        return statuses[section]?.needsAttention ?? false;
    }

    // Links into folded sections unfold them; so does a link someone shared, once the
    // report it points into has rendered.
    onMount(() => revealOnNavigation());

    // The report is fetched before the page stops loading, so it is only in the DOM once
    // both are settled.
    let revealedFor: string | null = null;
    $effect(() => {
        if (!report || loading || revealedFor === report.id || !window.location.hash) return;
        revealedFor = report.id;
        tick().then(() => revealHash(window.location.hash)?.scrollIntoView());
    });

    function showError(status: number | undefined, apiError: unknown, defaultMessage: string) {
        errorStatus = status ?? 500;
        error =
            (apiError instanceof Error ? apiError.message : apiMessage(apiError)) ?? defaultMessage;
    }

    function isRateLimited(apiError: unknown): boolean {
        return (
            !!apiError &&
            typeof apiError === "object" &&
            "error" in apiError &&
            apiError.error === "rate_limit_exceeded"
        );
    }

    async function fetchReport() {
        if (!testId) return;

        try {
            const reportResponse = await getReport({ path: { id: testId } });
            if (reportResponse.data) {
                reportRateLimited = false;
                report = reportResponse.data;
                stopPolling();
            } else if (reportResponse.error) {
                if (isRateLimited(reportResponse.error)) {
                    reportRateLimited = true;
                    reportRetryTimeout = setTimeout(fetchReport, 2000);
                } else {
                    showError(
                        reportResponse.response?.status,
                        reportResponse.error,
                        "Failed to fetch report",
                    );
                    stopPolling();
                }
            }
        } catch (err) {
            showError(500, err, "Failed to fetch report");
            stopPolling();
        }
    }

    async function fetchTest() {
        if (!testId) return;

        if (nbfetch > 0) {
            nextfetch = Math.max(nextfetch, Math.floor(3 + nbfetch * 0.5));
        }
        nbfetch += 1;

        // Clear any previous errors
        error = null;

        // Set fetching state and ensure minimum 500ms display time
        fetching = true;
        const startTime = Date.now();

        try {
            const testResponse = await getTest({ path: { id: testId } });
            if (testResponse.data) {
                test = testResponse.data;

                if (test.status === "analyzed" && !reportRetryTimeout) {
                    await fetchReport();
                }
            } else if (testResponse.error) {
                showError(
                    testResponse.response?.status,
                    testResponse.error,
                    "Failed to fetch test",
                );
                loading = false;
                stopPolling();
                return;
            }
            loading = false;
        } catch (err) {
            showError(500, err, "Failed to fetch test");
            loading = false;
            stopPolling();
        } finally {
            // Ensure fetching state is displayed for at least 500ms
            const elapsed = Date.now() - startTime;
            if (elapsed < 500) {
                setTimeout(() => {
                    fetching = false;
                }, 500 - elapsed);
            } else {
                fetching = false;
            }
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
        if (reportRetryTimeout) {
            clearTimeout(reportRetryTimeout);
            reportRetryTimeout = null;
        }
    }

    let lastTestId: string | null = null;
    function testChange(newTestId: string) {
        if (lastTestId != newTestId) {
            lastTestId = newTestId;
            test = null;
            fetchTest();
            startPolling();
        }
    }

    $effect(() => {
        const newTestId = page.params.test;
        if (newTestId) {
            testChange(newTestId);
        }
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
            } else if (response.error) {
                showError(response.response?.status, response.error, "Failed to reanalyze report");
            }
        } catch (err) {
            showError(500, err, "Failed to reanalyze report");
        } finally {
            reanalyzing = false;
        }
    }

    function handleExportJSON() {
        const dataStr = JSON.stringify(report, null, 2);
        const dataBlob = new Blob([dataStr], { type: "application/json" });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `report-${testId}.json`;
        link.click();
        URL.revokeObjectURL(url);
        menuOpen = false;
    }
</script>

<svelte:head>
    <title>
        {report
            ? `Test${report.dns_results ? ` of ${report.dns_results.from_domain}` : ""} ${report.test_id?.slice(0, 7) || ""}`
            : test
              ? `Test ${test.id.slice(0, 7)}`
              : "Loading..."} - HappyDeliver
    </title>
</svelte:head>

<div class="container py-5">
    {#if loading}
        <div class="text-center py-5">
            <TileLoader />
            <p class="mt-3 text-muted">Loading test...</p>
        </div>
    {:else if error}
        <ErrorDisplay status={errorStatus} message={error} showActions={false} />
    {:else if test && test.status !== "analyzed"}
        <!-- Pending State -->
        <PendingState
            {nextfetch}
            {nbfetch}
            {test}
            {fetching}
            on:force-inbox-check={() => fetchTest()}
        />
    {:else if reportRateLimited}
        <div class="text-center py-5">
            <TileLoader />
            <p class="mt-3 text-muted">Rate limited, retrying in a moment...</p>
        </div>
    {:else if report}
        <!-- Results State -->
        <div class="fade-in">
            <!-- Score Header -->
            <div class="row mb-4" id="score">
                <div class="col-12">
                    <div class="position-relative">
                        <div class="position-absolute py-2 px-3" style="z-index: 2; right: 0">
                            <div class="dropdown">
                                <button
                                    class="btn btn-outline-secondary"
                                    type="button"
                                    onclick={() => (menuOpen = !menuOpen)}
                                    aria-label="Menu"
                                >
                                    <i class="bi bi-three-dots-vertical"></i>
                                </button>
                                {#if menuOpen}
                                    <div
                                        class="dropdown-menu dropdown-menu-end show"
                                        data-bs-popper="static"
                                    >
                                        <button class="dropdown-item" onclick={handleExportJSON}>
                                            <i class="bi bi-download me-2"></i>
                                            Export JSON Report
                                        </button>
                                        <button
                                            class="dropdown-item"
                                            onclick={handleReanalyze}
                                            disabled={reanalyzing}
                                        >
                                            <i class="bi bi-arrow-clockwise me-2"></i>
                                            Reanalyze with Latest Version
                                        </button>
                                        <hr class="dropdown-divider" />
                                        <!-- eslint-disable svelte/no-navigation-without-resolve -- API endpoint, not a SvelteKit route -->
                                        <a
                                            class="dropdown-item"
                                            href={`/api/report/${testId}/raw.eml`}
                                            target="_blank"
                                            onclick={() => (menuOpen = false)}
                                        >
                                            <i class="bi bi-file-earmark-text me-2"></i>
                                            View Raw Email
                                        </a>
                                        <!-- eslint-enable svelte/no-navigation-without-resolve -->
                                    </div>
                                {/if}
                            </div>
                        </div>
                    </div>
                    <ScoreCard
                        grade={report.grade}
                        score={report.score}
                        summary={report.summary}
                        authentication={report.authentication}
                        source={report.source}
                        spamFilters={report}
                        blacklists={report}
                        {statuses}
                        {reanalyzing}
                    />
                </div>
            </div>

            <!-- Summary -->
            <div class="row mb-4">
                <div class="col-12">
                    <SummaryCard {report}>
                        <div class="d-flex justify-content-end me-lg-5">
                            <TinySurvey
                                class="bg-primary-subtle rounded-4 p-3 text-center"
                                source={report.id}
                            />
                        </div>
                    </SummaryCard>
                </div>
            </div>

            <!-- Received Chain -->
            {#if report.header_analysis?.received_chain && report.header_analysis.received_chain.length > 0}
                <div class="row mb-4" id="received-chain">
                    <div class="col-12">
                        <EmailPathCard receivedChain={report.header_analysis.received_chain} />
                    </div>
                </div>
            {/if}

            <!-- DNS Records -->
            {#if report.dns_results}
                <div class="row mb-4" id="dns">
                    <div class="col-12">
                        <DnsRecordsCard
                            domainAlignment={report.header_analysis?.domain_alignment}
                            alignmentIssues={report.header_analysis?.issues?.domain_alignment}
                            dnsResults={report.dns_results}
                            dnsGrade={report.summary?.dns_grade}
                            dnsScore={report.summary?.dns_score}
                            status={statuses.dns}
                            open={opens("dns")}
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
                            source={report.source}
                            authservId={report.authserv_id}
                            status={statuses.authentication}
                            open={opens("authentication")}
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
                            status={statuses.blacklist}
                            open={opens("blacklist")}
                        />
                    </div>
                </div>
            {/if}

            <!-- Domain Reputation -->
            {#if report.domain_reputation}
                <div class="row mb-4" id="domain-reputation">
                    <div class="col-12">
                        <DomainReputationCard
                            blacklist={report.domain_reputation}
                            domain={report.dns_results?.from_domain ?? ""}
                            class=""
                        />
                    </div>
                </div>
            {/if}

            <!-- Header Analysis -->
            {#if report.header_analysis}
                <div class="row mb-4" id="header">
                    <div class="col-12">
                        <HeaderAnalysisCard
                            dmarcRecord={report.dns_results?.dmarc_record}
                            headerAnalysis={report.header_analysis}
                            headerGrade={report.summary?.header_grade}
                            headerScore={report.summary?.header_score}
                            status={statuses.headers}
                            open={opens("headers")}
                        />
                    </div>
                </div>
            {/if}

            <!-- Spam filter analysis -->
            {#if report.spamassassin || report.rspamd}
                <div class="row mb-4" id="spam">
                    <div class="col-12">
                        <ReportSection
                            id="spam-details"
                            title="Spam Filters"
                            icon="bug"
                            grade={report.summary?.spam_grade}
                            score={report.summary?.spam_score}
                            status={statuses.spam}
                            open={opens("spam")}
                        >
                            <div class="card-body">
                                <div class="row g-3">
                                    {#if report.spamassassin}
                                        <div class={report.rspamd ? "col-lg-6" : "col-12"}>
                                            <SpamAssassinCard spamassassin={report.spamassassin} />
                                        </div>
                                    {/if}
                                    {#if report.rspamd}
                                        <div class={report.spamassassin ? "col-lg-6" : "col-12"}>
                                            <RspamdCard
                                                rspamd={report.rspamd}
                                                adviceAnchors={adviceAnchorsBySymbol(
                                                    report.content_analysis?.html_issues,
                                                )}
                                            />
                                        </div>
                                    {/if}
                                </div>
                            </div>
                        </ReportSection>
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
                            status={statuses.content}
                            open={opens("content")}
                        />
                    </div>
                </div>
            {/if}

            <!-- Attachment Analysis -->
            {#if report.attachment_analysis}
                <div class="row mb-4" id="attachments">
                    <div class="col-12">
                        <AttachmentAnalysisCard
                            attachmentAnalysis={report.attachment_analysis}
                            attachmentsGrade={report.summary?.attachments_grade}
                            attachmentsScore={report.summary?.attachments_score}
                            status={statuses.attachments}
                            open={opens("attachments")}
                        />
                    </div>
                </div>
            {/if}

            <!-- Whitelists: informational, they never weigh on the score -->
            {#if report.whitelists && Object.keys(report.whitelists).length > 0}
                <div class="row mb-4" id="whitelist">
                    <div class="col-12">
                        <WhitelistCard whitelists={report.whitelists} open={false} />
                    </div>
                </div>
            {/if}

            <!-- Action Buttons -->
            <div class="row">
                <div class="col-12 text-center">
                    <a href={resolve("test")} class="btn btn-primary btn-lg">
                        <i class="bi bi-arrow-repeat me-2"></i>
                        Test Another Email
                    </a>
                </div>
            </div>
        </div>
    {/if}
</div>
