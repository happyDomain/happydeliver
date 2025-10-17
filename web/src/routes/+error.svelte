<script lang="ts">
    import { page } from "$app/stores";

    let status = $derived($page.status);
    let message = $derived($page.error?.message || "An unexpected error occurred");

    function getErrorTitle(status: number): string {
        switch (status) {
            case 404:
                return "Page Not Found";
            case 403:
                return "Access Denied";
            case 500:
                return "Server Error";
            case 503:
                return "Service Unavailable";
            default:
                return "Something Went Wrong";
        }
    }

    function getErrorDescription(status: number): string {
        switch (status) {
            case 404:
                return "The page you're looking for doesn't exist or has been moved.";
            case 403:
                return "You don't have permission to access this resource.";
            case 500:
                return "Our server encountered an error while processing your request.";
            case 503:
                return "The service is temporarily unavailable. Please try again later.";
            default:
                return "An unexpected error occurred. Please try again.";
        }
    }

    function getErrorIcon(status: number): string {
        switch (status) {
            case 404:
                return "bi-search";
            case 403:
                return "bi-shield-lock";
            case 500:
                return "bi-exclamation-triangle";
            case 503:
                return "bi-clock-history";
            default:
                return "bi-exclamation-circle";
        }
    }
</script>

<svelte:head>
    <title>{status} - {getErrorTitle(status)} | happyDeliver</title>
</svelte:head>

<div class="container py-5">
    <div class="row justify-content-center">
        <div class="col-lg-6 text-center fade-in">
            <!-- Error Icon -->
            <div class="error-icon-wrapper mb-4">
                <i class="bi {getErrorIcon(status)} text-danger"></i>
            </div>

            <!-- Error Status -->
            <h1 class="display-1 fw-bold text-primary mb-3">{status}</h1>

            <!-- Error Title -->
            <h2 class="fw-bold mb-3">{getErrorTitle(status)}</h2>

            <!-- Error Description -->
            <p class="text-muted mb-4">{getErrorDescription(status)}</p>

            <!-- Error Message (if available) -->
            {#if message !== getErrorDescription(status)}
                <div class="alert alert-light border mb-4" role="alert">
                    <i class="bi bi-info-circle me-2"></i>
                    {message}
                </div>
            {/if}

            <!-- Action Buttons -->
            <div class="d-flex flex-column flex-sm-row gap-3 justify-content-center">
                <a href="/" class="btn btn-primary btn-lg px-4">
                    <i class="bi bi-house-door me-2"></i>
                    Go Home
                </a>
                <button
                    class="btn btn-outline-primary btn-lg px-4"
                    onclick={() => window.history.back()}
                >
                    <i class="bi bi-arrow-left me-2"></i>
                    Go Back
                </button>
            </div>

            <!-- Additional Help -->
            {#if status === 404}
                <div class="mt-5">
                    <p class="text-muted small mb-2">Looking for something specific?</p>
                    <div class="d-flex flex-wrap gap-2 justify-content-center">
                        <a href="/" class="badge bg-light text-dark text-decoration-none">Home</a>
                        <a href="/#features" class="badge bg-light text-dark text-decoration-none"
                            >Features</a
                        >
                        <a
                            href="https://github.com/happyDomain/happydeliver"
                            class="badge bg-light text-dark text-decoration-none"
                        >
                            Documentation
                        </a>
                    </div>
                </div>
            {/if}
        </div>
    </div>
</div>

<style>
    .error-icon-wrapper {
        font-size: 6rem;
        line-height: 1;
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

    .badge {
        padding: 0.5rem 1rem;
        font-weight: normal;
        transition: all 0.2s ease;
    }

    .badge:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }
</style>
