<script lang="ts">
    import { goto } from "$app/navigation";
    import { resolve } from "$app/paths";
    import { page } from "$app/state";

    import { listTests, createTest as apiCreateTest } from "#lib/api/index.js";
    import type { TestSummary } from "#lib/api/types.gen.js";
    import { ErrorDisplay, HistoryTable, TileLoader } from "#lib/components/index.js";
    import { apiMessage } from "#lib/errors.js";

    let tests = $state<TestSummary[]>([]);
    let total = $state(0);
    const limit = 20;
    let requestedPage = $derived(
        Math.max(1, parseInt(page.url.searchParams.get("page") ?? "1", 10) || 1),
    );
    let offset = $derived((requestedPage - 1) * limit);
    let loading = $state(true);
    let error = $state<string | null>(null);
    let errorStatus = $state(500);
    let creatingTest = $state(false);

    async function loadTests(offset: number) {
        loading = true;
        error = null;

        try {
            const response = await listTests({ query: { offset, limit } });
            if (response.response?.ok && response.data) {
                tests = response.data.tests;
                total = response.data.total;
            } else {
                errorStatus = response.response?.status ?? 500;
                error = apiMessage(response.error) ?? "Failed to load tests.";
            }
        } catch (err) {
            errorStatus = 500;
            error = err instanceof Error ? err.message : "Failed to load tests.";
        } finally {
            loading = false;
        }
    }

    $effect(() => {
        loadTests(offset);
    });

    function pageHref(n: number): string {
        return n <= 1 ? resolve("/history") : `${resolve("/history")}?page=${n}`;
    }

    async function createTest() {
        creatingTest = true;
        try {
            const response = await apiCreateTest();
            if (response.response?.ok && response.data) {
                goto(resolve("/test/[test]", { test: response.data.id }));
            } else {
                errorStatus = response.response?.status ?? 500;
                error = apiMessage(response.error) ?? "Failed to create test";
            }
        } catch (err) {
            errorStatus = 500;
            error = err instanceof Error ? err.message : "Failed to create test";
        } finally {
            creatingTest = false;
        }
    }

    let totalPages = $derived(Math.ceil(total / limit));
    let currentPage = $derived(Math.floor(offset / limit) + 1);
</script>

<svelte:head>
    <title>Test History - happyDeliver</title>
</svelte:head>

<div class="container py-5">
    <div class="row">
        <div class="col-lg-10 mx-auto">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h1 class="display-6 fw-bold mb-0">
                    <i class="bi bi-clock-history me-2"></i>
                    Test History
                </h1>
                <button class="btn btn-primary" onclick={createTest} disabled={creatingTest}>
                    {#if creatingTest}
                        <span class="spinner-border spinner-border-sm me-2" role="status"></span>
                    {:else}
                        <i class="bi bi-plus-lg me-1"></i>
                    {/if}
                    New Test
                </button>
            </div>

            {#if loading}
                <div class="text-center py-5">
                    <TileLoader />
                    <p class="mt-3 text-muted">Loading tests...</p>
                </div>
            {:else if error}
                <ErrorDisplay status={errorStatus} message={error} showActions={false} />
            {:else if tests.length === 0 && total > 0}
                <div class="text-center py-5">
                    <i class="bi bi-signpost-split display-1 text-muted mb-3 d-block"></i>
                    <h2 class="h4 text-muted mb-3">No tests on page {currentPage}</h2>
                    <p class="text-muted mb-4">
                        The history only has {totalPages}
                        {totalPages === 1 ? "page" : "pages"}.
                    </p>
                    <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- pageHref resolves the route -->
                    <a class="btn btn-primary" href={pageHref(totalPages)}>
                        <i class="bi bi-chevron-left me-1"></i>
                        Go to the last page
                    </a>
                </div>
            {:else if tests.length === 0}
                <div class="text-center py-5">
                    <i class="bi bi-inbox display-1 text-muted mb-3 d-block"></i>
                    <h2 class="h4 text-muted mb-3">No tests yet</h2>
                    <p class="text-muted mb-4">
                        Send a test email to get your first deliverability report.
                    </p>
                    <button
                        class="btn btn-primary btn-lg"
                        onclick={createTest}
                        disabled={creatingTest}
                    >
                        <i class="bi bi-envelope-plus me-2"></i>
                        Start Your First Test
                    </button>
                </div>
            {:else}
                <HistoryTable {tests} />

                <!-- Pagination -->
                {#if totalPages > 1}
                    <nav class="mt-4 d-flex justify-content-between align-items-center">
                        <small class="text-muted">
                            Showing {offset + 1}-{Math.min(offset + limit, total)} of {total} tests
                        </small>
                        <!-- eslint-disable svelte/no-navigation-without-resolve -- pageHref resolves the route -->
                        <ul class="pagination mb-0">
                            <li class="page-item" class:disabled={currentPage === 1}>
                                <a
                                    class="page-link"
                                    href={pageHref(currentPage - 1)}
                                    aria-disabled={currentPage === 1}
                                    tabindex={currentPage === 1 ? -1 : undefined}
                                >
                                    <i class="bi bi-chevron-left"></i>
                                    Previous
                                </a>
                            </li>
                            <li class="page-item disabled">
                                <span class="page-link">
                                    Page {currentPage} of {totalPages}
                                </span>
                            </li>
                            <li class="page-item" class:disabled={currentPage === totalPages}>
                                <a
                                    class="page-link"
                                    href={pageHref(currentPage + 1)}
                                    aria-disabled={currentPage === totalPages}
                                    tabindex={currentPage === totalPages ? -1 : undefined}
                                >
                                    Next
                                    <i class="bi bi-chevron-right"></i>
                                </a>
                            </li>
                        </ul>
                        <!-- eslint-enable svelte/no-navigation-without-resolve -->
                    </nav>
                {/if}
            {/if}
        </div>
    </div>
</div>
