<script lang="ts">
    import { page } from "$app/state";
    import { ErrorDisplay } from "$lib/components";

    let status = $derived(page.status);
    let message = $derived(page.error?.message || "An unexpected error occurred");

    function getErrorTitle(status: number): string {
        switch (status) {
            case 404:
                return "Page Not Found";
            case 403:
                return "Access Denied";
            case 429:
                return "Too Many Requests";
            case 500:
                return "Server Error";
            case 503:
                return "Service Unavailable";
            default:
                return "Something Went Wrong";
        }
    }
</script>

<svelte:head>
    <title>{status} - {getErrorTitle(status)} | happyDeliver</title>
</svelte:head>

<div class="container py-5">
    <ErrorDisplay {status} {message} />
</div>
