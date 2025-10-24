<script lang="ts">
    import { goto } from "$app/navigation";
    import { createTest as apiCreateTest } from "$lib/api";
    import { appConfig } from "$lib/config";
    import { FeatureCard, HowItWorksStep } from "$lib/components";

    let loading = $state(false);
    let error = $state<string | null>(null);

    async function createTest() {
        loading = true;
        error = null;

        try {
            const response = await apiCreateTest();
            if (response.data) {
                goto(`/test/${response.data.id}`);
            }
        } catch (err) {
            error = err instanceof Error ? err.message : "Failed to create test";
            loading = false;
        }
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
            description: "Send a test email from your mail server to the provided address.",
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
<section class="hero py-5" id="hero">
    <div class="container py-5">
        <div class="row align-items-center">
            <div class="col-lg-8 mx-auto text-center fade-in">
                <h1 class="display-3 fw-bold mb-4">Test Your Email Deliverability</h1>
                <p class="lead mb-4 opacity-90">
                    Get detailed insights into your email configuration, authentication, spam score,
                    and more. Open-source, self-hosted, and privacy-focused.
                </p>
                <button
                    class="btn btn-success btn-lg px-5 py-3 shadow"
                    onclick={createTest}
                    disabled={loading}
                >
                    {#if loading}
                        <span class="spinner-border spinner-border-sm me-2" role="status"></span>
                        Creating Test...
                    {:else}
                        <i class="bi bi-envelope-plus me-2"></i>
                        Start Free Test
                    {/if}
                </button>

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
            {#each features as feature}
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
            {#each steps as stepData}
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
    </div>
</section>

<style>
    .hero {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
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
</style>
