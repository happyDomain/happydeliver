<script lang="ts">
    import { goto } from "$app/navigation";
    import { resolve } from "$app/paths";

    import { createTest as apiCreateTest, listTests, uploadEml } from "$lib/api";
    import type { TestSummary } from "$lib/api/types.gen";
    import { FeatureCard, HowItWorksStep, HistoryTable } from "$lib/components";
    import { appConfig } from "$lib/stores/config";

    let loading = $state(false);
    let error = $state<string | null>(null);
    let recentTests = $state<TestSummary[]>([]);

    let fileInput = $state<HTMLInputElement | null>(null);
    let dragging = $state(false);

    async function loadRecentTests() {
        if (!$appConfig.test_list_enabled) return;
        try {
            const response = await listTests({ query: { offset: 0, limit: 5 } });
            if (response.data) {
                recentTests = response.data.tests;
            }
        } catch {
            // Silently ignore: this is a non-critical section
        }
    }

    $effect(() => {
        loadRecentTests();
    });

    async function createTest() {
        loading = true;
        error = null;

        try {
            const response = await apiCreateTest();
            if (response.data) {
                goto(resolve("/test/[test]", { test: response.data.id }));
            }
        } catch (err) {
            error = err instanceof Error ? err.message : "Failed to create test";
            loading = false;
        }
    }

    async function analyzeFile(file: File) {
        loading = true;
        error = null;

        try {
            const response = await uploadEml({ body: { file } });
            if (response.data) {
                goto(resolve("/test/[test]", { test: response.data.id }));
                return;
            }
            error = response.error?.message ?? "Failed to analyze this file";
        } catch (err) {
            error = err instanceof Error ? err.message : "Failed to analyze this file";
        }

        loading = false;
    }

    function onFileSelected(event: Event) {
        const input = event.currentTarget as HTMLInputElement;
        const file = input.files?.[0];

        // Reset the input so selecting the same file twice fires a new analysis
        input.value = "";

        if (file) analyzeFile(file);
    }

    function onDrop(event: DragEvent) {
        dragging = false;

        if (!$appConfig.eml_upload_enabled || loading) return;

        const file = event.dataTransfer?.files?.[0];
        if (file) analyzeFile(file);
    }

    function getMaxMessageSizeText(): string {
        const bytes = $appConfig.max_message_size;
        if (!bytes) return "";

        return `${Math.round(bytes / (1024 * 1024))} MB`;
    }

    function getRetentionTimeText(): string {
        if (!$appConfig.report_retention) return "ever";

        const seconds = $appConfig.report_retention / 1000000000;
        const days = Math.floor(seconds / 86400);
        const weeks = Math.floor(days / 7);
        const months = Math.floor(days / 30);

        if (months >= 1) {
            return months === 1 ? "1 month" : `${months} months`;
        } else if (weeks >= 1) {
            return weeks === 1 ? "1 week" : `${weeks} weeks`;
        } else if (days >= 1) {
            return days === 1 ? "1 day" : `${days} days`;
        } else {
            const hours = Math.floor(seconds / 3600);
            return hours === 1 ? "1 hour" : `${hours} hours`;
        }
    }

    const features = $derived([
        {
            icon: "bi-shield-check",
            title: "Authentication",
            description:
                "SPF, DKIM, DMARC, and BIMI validation with detailed results and recommendations.",
            variant: "primary" as const,
        },
        {
            icon: "bi-building-check",
            title: "BIMI Support",
            description:
                "Brand Indicators for Message Identification - verify your brand logo configuration.",
            variant: "info" as const,
        },
        {
            icon: "bi-link-45deg",
            title: "ARC Verification",
            description:
                "Authenticated Received Chain validation for forwarded emails and mailing lists.",
            variant: "primary" as const,
        },
        {
            icon: "bi-check2-circle",
            title: "Domain Alignment",
            description:
                "Verify alignment between From, Return-Path, and DKIM domains for DMARC compliance.",
            variant: "success" as const,
        },
        {
            icon: "bi-globe",
            title: "DNS Records",
            description:
                "Verify PTR, MX, SPF, DKIM, DMARC, and BIMI records are properly configured.",
            variant: "success" as const,
        },
        {
            icon: "bi-bug",
            title: "Spam Score",
            description: "SpamAssassin analysis with detailed test results and scoring.",
            variant: "warning" as const,
        },
        {
            icon: "bi-list-check",
            title: "Blacklists",
            description: "Check if your IP is listed in major DNS-based blacklists (RBLs).",
            variant: "danger" as const,
        },
        {
            icon: "bi-card-heading",
            title: "Header Quality",
            description: "Validate required headers, check for missing fields and alignment.",
            variant: "secondary" as const,
        },
        {
            icon: "bi-file-text",
            title: "Content Analysis",
            description: "HTML structure, link validation, image analysis, and more.",
            variant: "info" as const,
        },
        {
            icon: "bi-bar-chart",
            title: "Detailed Scoring",
            description:
                "A to F deliverability grade with breakdown by category and recommendations.",
            variant: "primary" as const,
        },
        {
            icon: "bi-file-earmark-arrow-up",
            title: "EML Upload",
            description:
                "Analyze a message you already received elsewhere: authentication results are read from the server that handled it.",
            variant: "info" as const,
        },
        {
            icon: "bi-lock",
            title: "Privacy First",
            description: `Self-hosted solution, your data never leaves your infrastructure. Reports retained for ${getRetentionTimeText()}.`,
            variant: "success" as const,
        },
    ]);

    const steps = [
        {
            step: 1,
            title: "Create Test",
            description: "Click the button to generate a unique test email address.",
        },
        {
            step: 2,
            title: "Send Email",
            description:
                "Send a test email from your mail server to the provided address, or upload an .eml file you already received.",
        },
        {
            step: 3,
            title: "View Results",
            description: "Get instant detailed analysis with actionable recommendations.",
        },
    ];
</script>

<svelte:head>
    <title>happyDeliver. Test Your Email Deliverability.</title>
</svelte:head>

<!-- Hero Section -->
<section
    class="hero py-5"
    class:dragging
    id="hero"
    ondragover={(e) => {
        if (!$appConfig.eml_upload_enabled) return;
        e.preventDefault();
        dragging = true;
    }}
    ondragleave={() => (dragging = false)}
    ondrop={(e) => {
        e.preventDefault();
        onDrop(e);
    }}
>
    <div class="container py-5">
        <div class="row align-items-center">
            <div class="col-lg-8 mx-auto text-center fade-in">
                <h1 class="display-3 fw-bold mb-4">Test Your Email Deliverability</h1>
                <p class="lead mb-4 opacity-90" style="text-wrap: balance;">
                    Get detailed insights into your email configuration, authentication, spam score,
                    and more. Open-source, self-hosted, and privacy-focused.
                </p>
                <button
                    class="btn btn-success btn-lg px-5 py-3 shadow cta-button"
                    onclick={createTest}
                    disabled={loading}
                >
                    {#if loading}
                        <span class="spinner-border spinner-border-sm me-2" role="status"></span>
                        Working...
                    {:else}
                        <i class="bi bi-envelope-plus me-2"></i>
                        Start Free Test
                    {/if}
                </button>

                {#if $appConfig.eml_upload_enabled}
                    <div class="mt-4">
                        <p class="mb-2 opacity-90" style="text-wrap: balance;">
                            Already received the message elsewhere?
                        </p>
                        <input
                            type="file"
                            accept=".eml,message/rfc822,text/plain"
                            class="d-none"
                            bind:this={fileInput}
                            onchange={onFileSelected}
                        />
                        <button
                            class="btn btn-outline-light btn-lg px-4"
                            onclick={() => fileInput?.click()}
                            disabled={loading}
                        >
                            <i class="bi bi-file-earmark-arrow-up me-2"></i>
                            Analyze an .eml file
                        </button>
                        <p class="small mt-2 mb-0 opacity-90" style="text-wrap: balance;">
                            Drop the raw file here{#if getMaxMessageSizeText()}&nbsp;({getMaxMessageSizeText()}
                                max){/if}. Authentication results are then read from the server that
                            actually received it.
                        </p>
                    </div>
                {/if}

                {#if error}
                    <div class="alert alert-danger mt-4 d-inline-block" role="alert">
                        <i class="bi bi-exclamation-triangle me-2"></i>
                        {error}
                    </div>
                {/if}
            </div>
        </div>
    </div>
</section>

<!-- Recently Tested -->
{#if $appConfig.test_list_enabled && recentTests.length > 0}
    <section class="py-5 border-bottom border-3" id="recent">
        <div class="container py-4">
            <div class="row text-center mb-5">
                <div class="col-lg-8 mx-auto">
                    <h2 class="display-5 fw-bold mb-3">Recently Tested</h2>
                    <p class="text-muted">Latest deliverability reports from this instance</p>
                </div>
            </div>

            <div class="row">
                <div class="col-lg-10 mx-auto">
                    <HistoryTable tests={recentTests} />
                    <div class="text-center mt-4">
                        <a href={resolve("/history")} class="btn btn-outline-primary">
                            <i class="bi bi-clock-history me-2"></i>
                            View All Tests
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </section>
{/if}

<!-- Features Section -->
<section class="py-5" id="features">
    <div class="container py-4">
        <div class="row text-center mb-5">
            <div class="col-lg-8 mx-auto">
                <h2 class="display-5 fw-bold mb-3">Comprehensive Email Analysis</h2>
                <p class="text-muted">
                    Your favorite deliverability tester, open-source and self-hostable for complete
                    privacy and control.
                </p>
            </div>
        </div>

        <div class="row g-4 justify-content-center">
            {#each features as feature (feature.title)}
                <div class="col-md-6 col-lg-3">
                    <FeatureCard {...feature} />
                </div>
            {/each}
        </div>
    </div>
</section>

<!-- How It Works -->
<section class="bg-light py-5" id="steps">
    <div class="container py-4">
        <div class="row text-center mb-5">
            <div class="col-lg-8 mx-auto">
                <h2 class="display-5 fw-bold mb-3">How It Works</h2>
                <p class="text-muted">
                    Simple three-step process to test your email deliverability
                </p>
            </div>
        </div>

        <div class="row g-4">
            {#each steps as stepData (stepData.title)}
                <div class="col-md-4">
                    <HowItWorksStep {...stepData} />
                </div>
            {/each}
        </div>

        <div class="text-center mt-5">
            <button
                class="btn btn-primary btn-lg px-5 py-3"
                onclick={createTest}
                disabled={loading}
            >
                {#if loading}
                    <span class="spinner-border spinner-border-sm me-2" role="status"></span>
                    Creating Test...
                {:else}
                    <i class="bi bi-rocket-takeoff me-2"></i>
                    Get Started Now
                {/if}
            </button>
        </div>

        <div class="text-center mt-4">
            {#if $appConfig.eml_upload_enabled}
                <button
                    class="btn btn-secondary btn-lg me-2"
                    onclick={() => fileInput?.click()}
                    disabled={loading}
                >
                    <i class="bi bi-file-earmark-arrow-up me-2"></i>
                    Analyze an .eml File
                </button>
            {/if}
            <a href={resolve("/domain")} class="btn btn-secondary btn-lg me-2">
                <i class="bi bi-globe me-2"></i>
                Test Domain Only
            </a>
            <a href={resolve("/blacklist")} class="btn btn-secondary btn-lg">
                <i class="bi bi-shield-exclamation me-2"></i>
                Check IP Blacklist
            </a>
        </div>
    </div>
</section>

<style>
    .hero {
        background:
            linear-gradient(135deg, rgba(102, 126, 234, 0.85) 0%, rgba(118, 75, 162, 0.9) 100%),
            url("/img/report.webp");
        background-size: cover;
        background-position: center 25%;
        background-repeat: no-repeat;
        color: white;
    }

    .hero h1,
    .hero p {
        text-shadow: black 0 0 1px;
    }

    .hero.dragging {
        outline: 3px dashed rgba(255, 255, 255, 0.9);
        outline-offset: -1rem;
    }

    /* Dark mode hero adjustments */
    :global([data-bs-theme="dark"]) .hero {
        background:
            linear-gradient(135deg, rgba(50, 65, 140, 0.85) 0%, rgba(65, 40, 95, 0.9) 100%),
            url("/img/report.webp");
        background-size: cover;
        background-position: center 25%;
        background-repeat: no-repeat;
    }

    :global([data-bs-theme="dark"]) .hero h1,
    :global([data-bs-theme="dark"]) .hero p {
        text-shadow: black 0 0 3px;
    }

    /* Dark mode section background */
    :global([data-bs-theme="dark"]) #steps {
        background-color: var(--bs-secondary-bg) !important;
    }

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

    .cta-button {
        position: relative;
        animation: pulse 2s infinite;
        transition: transform 0.2s ease;
    }

    .cta-button:hover:not(:disabled) {
        animation: none;
        transform: scale(1.05);
    }

    .cta-button:disabled {
        animation: none;
    }

    @keyframes pulse {
        0%,
        100% {
            transform: scale(1);
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
        }
        50% {
            transform: scale(1.08);
            box-shadow: 0 1rem 2rem rgba(25, 135, 84, 0.5);
        }
    }

    @keyframes pulse-dark {
        0%,
        100% {
            transform: scale(1);
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.4);
        }
        50% {
            transform: scale(1.08);
            box-shadow: 0 1rem 2rem rgba(25, 135, 84, 0.7);
        }
    }

    /* Dark mode pulse animation */
    :global([data-bs-theme="dark"]) .cta-button {
        animation: pulse-dark 2s infinite;
    }
</style>
