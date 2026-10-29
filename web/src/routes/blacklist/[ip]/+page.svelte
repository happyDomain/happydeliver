<script lang="ts">
    import { page } from "$app/state";
    import { resolve } from "$app/paths";
    import { onMount } from "svelte";
    import TileLoader from "#lib/components/TileLoader.svelte";
    import { checkBlacklist } from "#lib/api/index.js";
    import type { BlacklistCheckResponse } from "#lib/api/types.gen.js";
    import {
        BlacklistCard,
        ErrorDisplay,
        GradeDisplay,
        TinySurvey,
    } from "#lib/components/index.js";
    import { apiMessage } from "#lib/errors.js";

    let ip = $derived(page.params.ip);
    let loading = $state(true);
    let error = $state<string | null>(null);
    let errorStatus = $state(500);
    let result = $state<BlacklistCheckResponse | null>(null);

    async function analyzeIP() {
        loading = true;
        error = null;
        result = null;

        if (!ip) {
            errorStatus = 400;
            error = "IP parameter is missing";
            loading = false;
            return;
        }

        try {
            const response = await checkBlacklist({ body: { ip } });

            if (response.response?.ok && response.data) {
                result = response.data;
            } else {
                errorStatus = response.response?.status ?? 500;
                error = apiMessage(response.error) ?? "Failed to check IP address";
            }
        } catch (err) {
            errorStatus = 500;
            error = err instanceof Error ? err.message : "Failed to check IP address";
        } finally {
            loading = false;
        }
    }

    onMount(() => {
        analyzeIP();
    });
</script>

<svelte:head>
    <title>{ip} - Blacklist Check - HappyDeliver</title>
</svelte:head>

<div class="container py-5">
    <div class="row">
        <div class="col-lg-10 mx-auto">
            <!-- Header -->
            <div class="mb-4">
                <div class="d-flex align-items-center justify-content-between">
                    <h1 class="h2 mb-0">
                        <i class="bi bi-shield-exclamation me-2"></i>
                        Blacklist Analysis
                    </h1>

                    <a href={resolve("blacklist")} class="btn btn-outline-secondary">
                        <i class="bi bi-arrow-left me-2"></i>
                        Check Another IP
                    </a>
                </div>
            </div>

            {#if loading}
                <!-- Loading State -->
                <div class="card">
                    <div class="card-body text-center py-5">
                        <TileLoader class="mb-3" />
                        <h3 class="h5">Checking {ip}...</h3>
                        <p class="text-muted mb-0">Querying DNS-based blacklists</p>
                    </div>
                </div>
            {:else if error}
                <ErrorDisplay status={errorStatus} message={error} showActions={false}>
                    {#snippet actions()}
                        <button type="button" class="btn btn-primary" onclick={analyzeIP}>
                            <i class="bi bi-arrow-clockwise me-1"></i>
                            Try Again
                        </button>
                    {/snippet}
                </ErrorDisplay>
            {:else if result}
                <!-- Results -->
                <div class="fade-in">
                    <!-- Score Summary Card -->
                    <div class="card mb-4">
                        <div class="card-body p-4">
                            <div class="row align-items-center">
                                <div class="col-md-6 text-center text-md-start mb-3 mb-md-0">
                                    <h2 class="h2 mb-2">
                                        <span class="font-monospace text-truncate">{result.ip}</span
                                        >
                                    </h2>
                                    {#if result.listed_count === 0}
                                        <div class="alert alert-success mb-0 d-inline-block">
                                            <i class="bi bi-check-circle me-2"></i>
                                            <strong>Not Listed</strong>
                                            <p class="d-inline mb-0 mt-1 small">
                                                This IP address is not listed on any checked
                                                blacklists.
                                            </p>
                                        </div>
                                    {:else}
                                        <div class="alert alert-danger mb-0 d-inline-block">
                                            <i class="bi bi-exclamation-triangle me-2"></i>
                                            <strong
                                                >Listed on {result.listed_count} blacklist{result.listed_count >
                                                1
                                                    ? "s"
                                                    : ""}</strong
                                            >
                                            <p class="mb-0 mt-1 small">
                                                This IP address is listed on {result.listed_count} of
                                                {result.blacklists.length} checked blacklist{result
                                                    .blacklists.length > 1
                                                    ? "s"
                                                    : ""}.
                                            </p>
                                        </div>
                                    {/if}
                                </div>
                                <div class="offset-md-3 col-md-3 text-center">
                                    <div
                                        class="p-2 rounded text-center summary-card bg-body-tertiary"
                                    >
                                        <GradeDisplay score={result.score} grade={result.grade} />
                                        <small class="text-muted d-block">Blacklist Score</small>
                                    </div>
                                </div>
                            </div>
                            <div class="d-flex justify-content-end me-lg-5">
                                <TinySurvey
                                    class="bg-primary-subtle rounded-4 p-3 text-center"
                                    source={"rbl-" + result.ip}
                                />
                            </div>
                        </div>
                    </div>

                    <div class="row">
                        <div class="col-12">
                            <BlacklistCard
                                blacklists={{ [result.ip]: result.blacklists }}
                                whitelists={result.whitelists
                                    ? { [result.ip]: result.whitelists }
                                    : undefined}
                                issues={{ [result.ip]: result.issues ?? [] }}
                                blacklistScore={result.score}
                                blacklistGrade={result.grade}
                            />
                        </div>
                    </div>

                    <!-- Information Card -->
                    <div class="card mt-4">
                        <div class="card-body">
                            <h3 class="h5 mb-3">
                                <i class="bi bi-info-circle me-2"></i>
                                What This Means
                            </h3>
                            {#if result.listed_count === 0}
                                <p class="mb-3">
                                    <strong>Good news!</strong> This IP address is not currently listed
                                    on any of the checked DNS-based blacklists (RBLs). This indicates
                                    a good sender reputation and should not negatively impact email deliverability.
                                </p>
                            {:else}
                                <p class="mb-3">
                                    <strong>Warning:</strong> This IP address is listed on {result.listed_count}
                                    blacklist{result.listed_count > 1 ? "s" : ""}. Being listed can
                                    significantly impact email deliverability as many mail servers
                                    use these blacklists to filter incoming mail.
                                </p>
                                <div class="alert alert-warning">
                                    <h4 class="h6 mb-2">Recommended Actions:</h4>
                                    <ul class="mb-0 small">
                                        <li>
                                            Investigate the cause of the listing (compromised
                                            system, spam complaints, etc.)
                                        </li>
                                        <li>
                                            Fix any security issues or stop sending practices that
                                            led to the listing
                                        </li>
                                        <li>
                                            Request delisting from each RBL (check their websites
                                            for removal procedures)
                                        </li>
                                        <li>
                                            Monitor your IP reputation regularly to prevent future
                                            listings
                                        </li>
                                    </ul>
                                </div>
                            {/if}
                        </div>
                    </div>

                    <!-- Next Steps -->
                    <div class="card border-primary mt-4">
                        <div class="card-body">
                            <h3 class="h5 mb-3">
                                <i class="bi bi-lightbulb me-2"></i>
                                Want Complete Email Analysis?
                            </h3>
                            <p class="mb-3">
                                This blacklist check tests IP reputation only. For comprehensive
                                deliverability testing including DKIM verification, content
                                analysis, spam scoring, and DNS configuration:
                            </p>
                            <a href={resolve("/")} class="btn btn-primary">
                                <i class="bi bi-envelope-plus me-2"></i>
                                Send Test Email
                            </a>
                        </div>
                    </div>
                </div>
            {/if}
        </div>
    </div>
</div>

<style>
    .summary-card {
        transition: transform 0.2s ease;
    }

    .summary-card:hover {
        transform: scale(1.05);
    }
</style>
