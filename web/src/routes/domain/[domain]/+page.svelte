<script lang="ts">
    import { page } from "$app/state";
    import { resolve } from "$app/paths";
    import { onMount } from "svelte";
    import TileLoader from "#lib/components/TileLoader.svelte";

    import { testDomain, testMailServers } from "#lib/api/index.js";
    import type { DomainTestResponse, MailServersResult } from "#lib/api/types.gen.js";
    import {
        DnsRecordsCard,
        DomainReputationCard,
        ErrorDisplay,
        MailServersCard,
        ScoreLink,
        TinySurvey,
    } from "#lib/components/index.js";
    import { apiMessage } from "#lib/errors.js";
    import { appConfig } from "#lib/stores/config.js";

    let domain = $derived(page.params.domain);
    let loading = $state(true);
    let error = $state<string | null>(null);
    let errorStatus = $state(500);
    let result = $state<DomainTestResponse | null>(null);

    let blacklist = $derived(result?.domain_reputation ?? null);

    // The probes of the mail servers take longer than the rest: they are asked
    // for at the same time, and shown when they come.
    const mxProbes = $derived(!!$appConfig.mx_probes_enabled);
    let mailServers = $state<MailServersResult | null>(null);
    let mailServersLoading = $state(false);
    let mailServersError = $state<string | null>(null);

    async function probeMailServers(name: string) {
        mailServers = null;
        mailServersError = null;
        mailServersLoading = true;
        try {
            const response = await testMailServers({ body: { domain: name } });
            if (name !== domain) return;
            if (response.response?.ok && response.data) {
                mailServers = response.data;
            } else {
                mailServersError =
                    apiMessage(response.error) ?? "The mail servers could not be probed";
            }
        } catch (err) {
            if (name !== domain) return;
            mailServersError =
                err instanceof Error ? err.message : "The mail servers could not be probed";
        } finally {
            if (name === domain) mailServersLoading = false;
        }
    }

    async function analyzeDomain() {
        loading = true;
        error = null;
        result = null;

        if (!domain) {
            errorStatus = 400;
            error = "Domain parameter is missing";
            loading = false;
            return;
        }

        if (mxProbes) probeMailServers(domain);

        try {
            const response = await testDomain({ body: { domain } });

            if (response.response?.ok && response.data) {
                result = response.data;
            } else {
                errorStatus = response.response?.status ?? 500;
                error = apiMessage(response.error) ?? "Failed to analyze domain";
            }
        } catch (err) {
            errorStatus = 500;
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
    <title>{domain} - Domain Test - HappyDeliver</title>
</svelte:head>

<div class="container py-5">
    <div class="row">
        <div class="col-lg-10 mx-auto">
            <!-- Header -->
            <div class="mb-4">
                <div class="d-flex align-items-center justify-content-between">
                    <h1 class="h2 mb-0"><i class="bi bi-globe me-2"></i>Domain Analysis</h1>

                    <a href={resolve("domain")} class="btn btn-outline-secondary">
                        <i class="bi bi-arrow-left me-2"></i>
                        Test Another Domain
                    </a>
                </div>
            </div>

            {#if loading}
                <!-- Loading State -->
                <div class="card border-0">
                    <div class="card-body text-center py-5">
                        <TileLoader class="mb-3" />
                        <h3 class="h5">Analyzing {domain}...</h3>
                        <p class="text-muted mb-0">
                            Checking DNS records, receiving policies and domain reputation
                        </p>
                    </div>
                </div>
            {:else if error}
                <ErrorDisplay status={errorStatus} message={error} showActions={false}>
                    {#snippet actions()}
                        <button type="button" class="btn btn-primary" onclick={analyzeDomain}>
                            <i class="bi bi-arrow-clockwise me-1"></i>
                            Try Again
                        </button>
                    {/snippet}
                </ErrorDisplay>
            {:else if result}
                <!-- Results -->
                <div class="fade-in">
                    <!-- Score Summary Card -->
                    <div class="card border-0 mb-4">
                        <div class="card-body p-4">
                            <div class="row align-items-center">
                                <div class="col-md-6 text-center text-md-start mb-3 mb-md-0">
                                    <h2 class="h2 mb-2">
                                        <span class="font-monospace">{result.domain}</span>
                                    </h2>
                                    {#if result.dns_results.from_domain_info?.disposable}
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
                                        class="score-tiles d-flex justify-content-md-end justify-content-center gap-3"
                                    >
                                        <div class="score-tile">
                                            <ScoreLink
                                                href="#dns-details"
                                                label="DNS"
                                                grade={result.grade}
                                                score={result.score}
                                            />
                                        </div>
                                        {#if mxProbes}
                                            <div class="score-tile">
                                                <ScoreLink
                                                    href="#mail-servers-details"
                                                    label="Mail Servers"
                                                    grade={mailServers?.grade ??
                                                        (mailServersLoading ? undefined : "?")}
                                                    score={mailServers?.score}
                                                    unavailable={!mailServersLoading &&
                                                        mailServers?.score === undefined}
                                                    tooltipTitle={mailServersLoading
                                                        ? "Probing the mail servers…"
                                                        : mailServers?.status === "inconclusive"
                                                          ? "Inconclusive: this instance cannot reach port 25"
                                                          : "Not graded"}
                                                />
                                            </div>
                                        {/if}
                                        {#if blacklist}
                                            <div class="score-tile">
                                                <ScoreLink
                                                    href="#reputation-details"
                                                    label="Reputation"
                                                    grade={blacklist.grade ?? "?"}
                                                />
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
                        mailPolicies={result.mail_policies}
                    />

                    <!-- Mail Servers: what a sending server sees -->
                    {#if mxProbes}
                        <MailServersCard
                            result={mailServers}
                            loading={mailServersLoading}
                            error={mailServersError}
                        />
                    {/if}

                    <!-- Domain Reputation / Blacklist -->
                    {#if blacklist}
                        <DomainReputationCard {blacklist} domain={result.domain} open />
                    {/if}

                    <!-- Next Steps -->
                    <div class="card border-primary mt-4">
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
                            <a href={resolve("/")} class="btn btn-primary">
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
    .score-tiles {
        width: 18rem;
    }

    .score-tile {
        flex: 1;
    }
</style>
