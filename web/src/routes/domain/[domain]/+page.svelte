<script lang="ts">
    import { page } from "$app/state";
    import { onMount } from "svelte";

    import { testDomain } from "$lib/api";
    import type { DomainTestResponse } from "$lib/api/types.gen";
    import { DnsRecordsCard, DomainBlacklistCard, GradeDisplay, TinySurvey } from "$lib/components";
    import { theme } from "$lib/stores/theme";

    let domain = $derived(page.params.domain);
    let loading = $state(true);
    let error = $state<string | null>(null);
    let result = $state<DomainTestResponse | null>(null);

    let blacklist = $derived(result?.blacklist ?? null);

    let blacklistSummary = $derived.by(() => {
        if (!blacklist) return null;
        const enabled = blacklist.results.filter((r) => r.enabled);
        const disabled = blacklist.results.length - enabled.length;
        const errored = enabled.filter((r) => r.error).length;
        const listed = enabled.filter((r) => r.listed);
        const critical = listed.filter((r) => r.severity === "crit").length;
        return {
            total: blacklist.results.length,
            enabled: enabled.length,
            disabled,
            errored,
            listed: listed.length,
            critical,
        };
    });

    type Verdict = "danger" | "warn" | "inconclusive" | "ok";

    let blacklistVerdict = $derived.by<Verdict | null>(() => {
        const s = blacklistSummary;
        if (!s) return null;
        if (s.critical > 0) return "danger";
        if (s.listed > 0) return "warn";
        if (s.enabled > 0 && s.errored === s.enabled) return "inconclusive";
        return "ok";
    });

    function formatCollectedAt(iso: string): string {
        try {
            return new Date(iso).toLocaleString();
        } catch {
            return iso;
        }
    }

    async function analyzeDomain() {
        loading = true;
        error = null;
        result = null;

        if (!domain) {
            error = "Domain parameter is missing";
            loading = false;
            return;
        }

        try {
            const response = await testDomain({
                body: { domain: domain },
            });

            if (response.data) {
                result = response.data;
            } else if (response.error) {
                error = response.error.message || "Failed to analyze domain";
            }
        } catch (err) {
            error = err instanceof Error ? err.message : "Failed to analyze domain";
        } finally {
            loading = false;
        }
    }

    onMount(() => {
        analyzeDomain();
    });
</script>

<svelte:head>
    <title>{domain} - Domain Test - happyDeliver</title>
</svelte:head>

<div class="container py-5">
    <div class="row">
        <div class="col-lg-10 mx-auto">
            <!-- Header -->
            <div class="mb-4">
                <div class="d-flex align-items-center justify-content-between">
                    <h1 class="h2 mb-0">
                        <i class="bi bi-globe me-2"></i>
                        Domain Analysis
                    </h1>
                    <a href="/domain" class="btn btn-outline-secondary">
                        <i class="bi bi-arrow-left me-2"></i>
                        Test Another Domain
                    </a>
                </div>
            </div>

            {#if loading}
                <!-- Loading State -->
                <div class="card shadow-sm">
                    <div class="card-body text-center py-5">
                        <div class="spinner-border text-primary mb-3" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        <h3 class="h5">Analyzing {domain}...</h3>
                        <p class="text-muted mb-0">
                            Checking DNS records, configuration and domain reputation
                        </p>
                    </div>
                </div>
            {:else if error}
                <!-- Error State -->
                <div class="card shadow-sm">
                    <div class="card-body text-center py-5">
                        <i class="bi bi-exclamation-triangle text-danger" style="font-size: 4rem;"
                        ></i>
                        <h3 class="h4 mt-4">Analysis Failed</h3>
                        <p class="text-muted mb-4">{error}</p>
                        <button class="btn btn-primary" onclick={analyzeDomain}>
                            <i class="bi bi-arrow-clockwise me-2"></i>
                            Try Again
                        </button>
                    </div>
                </div>
            {:else if result}
                <!-- Results -->
                <div class="fade-in">
                    <!-- Score Summary Card -->
                    <div class="card shadow-sm mb-4">
                        <div class="card-body p-4">
                            <div class="row align-items-center">
                                <div class="col-md-6 text-center text-md-start mb-3 mb-md-0">
                                    <h2 class="h2 mb-2">
                                        <span class="font-monospace">{result.domain}</span>
                                    </h2>
                                    {#if result.is_disposable}
                                        <div class="alert alert-warning mb-0 d-inline-block">
                                            <i class="bi bi-exclamation-triangle me-2"></i>
                                            <strong>Disposable Email Provider Detected</strong>
                                            <p class="mb-0 mt-1 small">
                                                This domain is a known temporary/disposable email
                                                service. Emails from this domain may have lower
                                                deliverability.
                                            </p>
                                        </div>
                                    {:else}
                                        <p class="text-muted mb-0">Domain Configuration Score</p>
                                    {/if}
                                </div>
                                <div class="col-md-6">
                                    <div
                                        class="d-flex justify-content-md-end justify-content-center gap-3"
                                    >
                                        <div
                                            class="p-2 rounded text-center summary-card"
                                            class:bg-light={$theme === "light"}
                                            class:bg-secondary={$theme !== "light"}
                                        >
                                            <GradeDisplay
                                                score={result.score}
                                                grade={result.grade}
                                            />
                                            <small class="text-muted d-block">DNS</small>
                                        </div>
                                        {#if blacklist}
                                            <div
                                                class="p-2 rounded text-center summary-card"
                                                class:bg-light={$theme === "light"}
                                                class:bg-secondary={$theme !== "light"}
                                            >
                                                <GradeDisplay grade={blacklist.grade ?? "?"} />
                                                <small class="text-muted d-block">Reputation</small>
                                            </div>
                                        {/if}
                                    </div>
                                </div>
                            </div>
                            <div class="d-flex justify-content-end me-lg-5 mt-3">
                                <TinySurvey
                                    class="bg-primary-subtle rounded-4 p-3 text-center"
                                    source={"domain-" + result.domain}
                                />
                            </div>
                        </div>
                    </div>

                    <!-- DNS Records Card -->
                    <DnsRecordsCard
                        dnsResults={result.dns_results}
                        dnsScore={result.score}
                        dnsGrade={result.grade}
                        domainOnly={true}
                    />

                    <!-- Domain Reputation / Blacklist -->
                    {#if blacklist && blacklistSummary}
                        <div class="card shadow-sm mt-4">
                            <div class="card-body p-4">
                                <div class="row align-items-center">
                                    <div class="col-md-7 text-center text-md-start mb-3 mb-md-0">
                                        <h3 class="h5 mb-2">
                                            <i class="bi bi-shield-shaded me-2"></i>
                                            Domain Reputation
                                        </h3>
                                        {#if blacklist.registered_domain && blacklist.registered_domain !== result.domain}
                                            <p class="text-muted small mb-2">
                                                Registered domain:
                                                <code>{blacklist.registered_domain}</code>
                                            </p>
                                        {/if}

                                        {#if blacklistVerdict === "danger"}
                                            <div class="alert alert-danger mb-0 d-inline-block">
                                                <i class="bi bi-exclamation-octagon me-2"></i>
                                                <strong
                                                    >Listed on {blacklistSummary.critical} high-severity
                                                    source{blacklistSummary.critical > 1
                                                        ? "s"
                                                        : ""}</strong
                                                >
                                                <p class="mb-0 mt-1 small">
                                                    This domain is reported by sources flagged
                                                    <em>critical</em>. Take action to delist.
                                                </p>
                                            </div>
                                        {:else if blacklistVerdict === "warn"}
                                            <div class="alert alert-warning mb-0 d-inline-block">
                                                <i class="bi bi-exclamation-triangle me-2"></i>
                                                <strong
                                                    >Listed on {blacklistSummary.listed} source{blacklistSummary.listed >
                                                    1
                                                        ? "s"
                                                        : ""}</strong
                                                >
                                                <p class="mb-0 mt-1 small">
                                                    Listed without critical severity — review the
                                                    source verdicts below.
                                                </p>
                                            </div>
                                        {:else if blacklistVerdict === "inconclusive"}
                                            <div class="alert alert-warning mb-0 d-inline-block">
                                                <i class="bi bi-question-octagon me-2"></i>
                                                <strong>Inconclusive</strong>
                                                <p class="mb-0 mt-1 small">
                                                    All enabled sources returned errors. Try again
                                                    later.
                                                </p>
                                            </div>
                                        {:else}
                                            <div class="alert alert-success mb-0 d-inline-block">
                                                <i class="bi bi-check-circle me-2"></i>
                                                <strong>No source reports this domain</strong>
                                                <p class="mb-0 mt-1 small">
                                                    Clean across all {blacklistSummary.enabled} enabled
                                                    source{blacklistSummary.enabled > 1 ? "s" : ""}.
                                                </p>
                                            </div>
                                        {/if}
                                    </div>
                                    <div class="col-md-5 text-center">
                                        <div
                                            class="p-3 rounded summary-card"
                                            class:bg-light={$theme === "light"}
                                            class:bg-secondary={$theme !== "light"}
                                        >
                                            <div class="d-flex justify-content-around mb-2">
                                                <div>
                                                    <div class="h4 mb-0">
                                                        {blacklistSummary.enabled}
                                                    </div>
                                                    <small class="text-muted">Enabled</small>
                                                </div>
                                                <div>
                                                    <div class="h4 mb-0 text-danger">
                                                        {blacklistSummary.listed}
                                                    </div>
                                                    <small class="text-muted">Listed</small>
                                                </div>
                                                <div>
                                                    <div class="h4 mb-0 text-secondary">
                                                        {blacklistSummary.disabled}
                                                    </div>
                                                    <small class="text-muted">Disabled</small>
                                                </div>
                                            </div>
                                            {#if blacklistSummary.errored > 0}
                                                <small class="text-muted d-block">
                                                    {blacklistSummary.errored} source{blacklistSummary.errored >
                                                    1
                                                        ? "s"
                                                        : ""} errored
                                                </small>
                                            {/if}
                                            <small class="text-muted d-block">
                                                Collected {formatCollectedAt(
                                                    blacklist.collected_at,
                                                )}
                                            </small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <DomainBlacklistCard results={blacklist.results} />
                    {/if}

                    <!-- Next Steps -->
                    <div class="card shadow-sm border-primary mt-4">
                        <div class="card-body">
                            <h3 class="h5 mb-3">
                                <i class="bi bi-lightbulb me-2"></i>
                                Want Complete Email Analysis?
                            </h3>
                            <p class="mb-3">
                                This domain test checks DNS configuration and domain reputation. For
                                comprehensive deliverability testing including DKIM verification,
                                content analysis, spam scoring, and sending-IP blacklist checks:
                            </p>
                            <a href="/" class="btn btn-primary">
                                <i class="bi bi-envelope-plus me-2"></i>
                                Send a Test Email
                            </a>
                        </div>
                    </div>
                </div>
            {/if}
        </div>
    </div>
</div>

<style>
    .fade-in {
        animation: fadeIn 0.5s ease-out;
    }

    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(15px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    .card {
        border: none;
    }
</style>
