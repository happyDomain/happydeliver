<script lang="ts">
    import { goto } from "$app/navigation";

    import { listTests, createTest as apiCreateTest } from "$lib/api";
    import type { TestSummary } from "$lib/api/types.gen";
    import { HistoryTable } from "$lib/components";

    let tests = $state<TestSummary[]>([]);
    let total = $state(0);
    let offset = $state(0);
    let limit = $state(20);
    let loading = $state(true);
    let error = $state<string | null>(null);
    let creatingTest = $state(false);

    async function loadTests() {
        loading = true;
        error = null;

        try {
            const response = await listTests({ query: { offset, limit } });
            if (response.data) {
                tests = response.data.tests;
                total = response.data.total;
            } else if (response.error) {
                if (
                    response.error &&
                    typeof response.error === "object" &&
                    "error" in response.error &&
                    response.error.error === "feature_disabled"
                ) {
                    error = "Test listing is disabled on this instance.";
                } else {
                    error = "Failed to load tests.";
                }
            }
        } catch (err) {
            error = err instanceof Error ? err.message : "Failed to load tests.";
        } finally {
            loading = false;
        }
    }

    $effect(() => {
        loadTests();
    });

    function goToPage(newOffset: number) {
        offset = newOffset;
        loadTests();
    }

    async function createTest() {
        creatingTest = true;
        try {
            const response = await apiCreateTest();
            if (response.data) {
                goto(`/test/${response.data.id}`);
            }
        } catch (err) {
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
                <button
                    class="btn btn-primary"
                    onclick={createTest}
                    disabled={creatingTest}
                >
                    {#if creatingTest}
                        <span
                            class="spinner-border spinner-border-sm me-2"
                            role="status"
                        ></span>
                    {:else}
                        <i class="bi bi-plus-lg me-1"></i>
                    {/if}
                    New Test
                </button>
            </div>

            {#if loading}
                <div class="text-center py-5">
                    <div
                        class="spinner-border text-primary"
                        role="status"
                        style="width: 3rem; height: 3rem;"
                    >
                        <span class="visually-hidden">Loading...</span>
                    </div>
                    <p class="mt-3 text-muted">Loading tests...</p>
                </div>
            {:else if error}
                <div class="alert alert-warning text-center" role="alert">
                    <i class="bi bi-exclamation-triangle me-2"></i>
                    {error}
                </div>
            {:else if tests.length === 0}
                <div class="text-center py-5">
                    <i
                        class="bi bi-inbox display-1 text-muted mb-3 d-block"
                    ></i>
                    <h2 class="h4 text-muted mb-3">No tests yet</h2>
                    <p class="text-muted mb-4">
                        Send a test email to get your first deliverability
                        report.
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
                            Showing {offset + 1}-{Math.min(
                                offset + limit,
                                total,
                            )} of {total} tests
                        </small>
                        <ul class="pagination mb-0">
                            <li
                                class="page-item"
                                class:disabled={currentPage === 1}
                            >
                                <button
                                    class="page-link"
                                    onclick={() =>
                                        goToPage(
                                            Math.max(0, offset - limit),
                                        )}
                                    disabled={currentPage === 1}
                                >
                                    <i class="bi bi-chevron-left"></i>
                                    Previous
                                </button>
                            </li>
                            <li class="page-item disabled">
                                <span class="page-link">
                                    Page {currentPage} of {totalPages}
                                </span>
                            </li>
                            <li
                                class="page-item"
                                class:disabled={currentPage === totalPages}
                            >
                                <button
                                    class="page-link"
                                    onclick={() =>
                                        goToPage(offset + limit)}
                                    disabled={currentPage === totalPages}
                                >
                                    Next
                                    <i class="bi bi-chevron-right"></i>
                                </button>
                            </li>
                        </ul>
                    </nav>
                {/if}
            {/if}
        </div>
    </div>
</div>
