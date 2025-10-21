<script lang="ts">
    import type { Check } from "$lib/api/types.gen";

    interface Props {
        check: Check;
    }

    let { check }: Props = $props();

    function getCheckIcon(status: string): string {
        switch (status) {
            case "pass":
                return "bi-check-circle-fill text-success";
            case "fail":
                return "bi-x-circle-fill text-danger";
            case "warn":
                return "bi-exclamation-triangle-fill text-warning";
            case "info":
                return "bi-info-circle-fill text-info";
            default:
                return "bi-question-circle-fill text-secondary";
        }
    }
</script>

<div class="card mb-3">
    <div class="card-body">
        <div class="d-flex align-items-start gap-3">
            <div class="fs-4">
                <i class={getCheckIcon(check.status)}></i>
            </div>
            <div class="flex-grow-1">
                <div class="d-flex justify-content-between align-items-start">
                    <h5 class="fw-bold mb-1">{check.name}</h5>
                    <span class="badge bg-light text-dark">{check.score}%</span>
                </div>

                <p class="mt-2 mb-2">{check.message}</p>

                {#if check.advice}
                    <div class="alert alert-light border mb-2" role="alert">
                        <i class="bi bi-lightbulb me-2"></i>
                        <strong>Recommendation:</strong>
                        {check.advice}
                    </div>
                {/if}

                {#if check.details}
                    <details class="small text-muted">
                        <summary class="cursor-pointer">Technical Details</summary>
                        <pre class="mt-2 mb-0 small bg-light p-2 rounded" style="white-space: pre-wrap;">{check.details}</pre>
                    </details>
                {/if}
            </div>
        </div>
    </div>
</div>

<style>
    .cursor-pointer {
        cursor: pointer;
    }

    details summary {
        user-select: none;
    }

    details summary:hover {
        color: var(--bs-primary);
    }
</style>
