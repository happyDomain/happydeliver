<script lang="ts">
    import { page } from "$app/state";
    import { ErrorDisplay } from "#lib/components/index.js";
</script>

<svelte:head>
    <title>Error {page.status} | HappyDeliver</title>
</svelte:head>

<div class="flex-fill d-flex flex-column justify-content-center bg-primary-subtle">
    <div class="container py-4 py-lg-5">
        <ErrorDisplay status={page.status} message={page.error?.message} />
    </div>
</div>
