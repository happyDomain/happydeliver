<script lang="ts">
    import { page } from "$app/stores";
    import { onMount } from "svelte";
    import { checkBlacklist } from "$lib/api";
    import type { BlacklistCheckResponse } from "$lib/api/types.gen";
    import { BlacklistCard, GradeDisplay, TinySurvey } from "$lib/components";
    import { theme } from "$lib/stores/theme";

    let ip = $derived($page.params.ip);
    let loading = $state(true);
    let error = $state<string | null>(null);
    let result = $state<BlacklistCheckResponse | null>(null);

    async function analyzeIP() {
        loading = true;
        error = null;
        result = null;

        if (!ip) {
            error = "IP parameter is missing";
            loading = false;
            return;
        }

        try {
            const response = await checkBlacklist({
                body: { ip: ip },
            });

            if (response.response.ok) {
                result = response.data;
            } else if (response.error) {
                error = response.error.message || "Failed to check IP address";
            }
        } catch (err) {
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
    <title>{ip} - Blacklist Check - happyDeliver</title>
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
                    <a href="/blacklist" class="btn btn-outline-secondary">
                        <i class="bi bi-arrow-left me-2"></i>
                        Check Another IP
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
                        <h3 class="h5">Checking {ip}...</h3>
                        <p class="text-muted mb-0">Querying DNS-based blacklists</p>
                    </div>
                </div>
            {:else if error}
                <!-- Error State -->
                <div class="card shadow-sm">
                    <div class="card-body text-center py-5">
                        <i class="bi bi-exclamation-triangle text-danger" style="font-size: 4rem;"
                        ></i>
                        <h3 class="h4 mt-4">Check Failed</h3>
                        <p class="text-muted mb-4">{error}</p>
                        <button class="btn btn-primary" onclick={analyzeIP}>
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
                                                {result.checks.length} checked blacklist{result
                                                    .checks.length > 1
                                                    ? "s"
                                                    : ""}.
                                            </p>
                                        </div>
                                    {/if}
                                </div>
                                <div class="offset-md-3 col-md-3 text-center">
                                    <div
                                        class="p-2 rounded text-center summary-card"
                                        class:bg-light={$theme === "light"}
                                        class:bg-secondary={$theme !== "light"}
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

                    <!-- Blacklist Results Card -->
                    <BlacklistCard
                        blacklists={{ [result.ip]: result.checks }}
                        blacklistScore={result.score}
                        blacklistGrade={result.grade}
                    />

                    <!-- Information Card -->
                    <div class="card shadow-sm mt-4">
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
                    <div class="card shadow-sm border-primary mt-4">
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
                            <a href="/" class="btn btn-primary">
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
    .fade-in {
        animation: fadeIn 0.5s ease-in;
    }

    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    .summary-card {
        transition: transform 0.2s ease;
    }

    .summary-card:hover {
        transform: scale(1.05);
    }

    .table td {
        vertical-align: middle;
    }

    .badge {
        font-size: 0.75rem;
        padding: 0.35rem 0.65rem;
    }
</style>
