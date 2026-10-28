<script lang="ts">
    import { resolve } from "$app/paths";
    import { page } from "$app/state";
    import { onMount, type Snippet } from "svelte";

    interface Props {
        status: number;
        message?: string | null;
        showActions?: boolean;
        // What the page can offer besides going home or back, such as trying again.
        actions?: Snippet;
    }

    let { status, message = null, showActions = true, actions }: Props = $props();

    // When it happened, frozen: the details must not drift while the user
    // reads them.
    const occurredAt = new Date();

    let canGoBack = $state(false);

    onMount(() => {
        canGoBack = window.history.length > 1;
    });

    const kind = $derived(
        status === 404
            ? "not-found"
            : status === 401 || status === 403
              ? "forbidden"
              : "unexpected",
    );

    const content = $derived(
        {
            "not-found": {
                icon: "bi-search",
                title: "Page Not Found",
                text: "The page you're looking for doesn't exist or has been moved.",
            },
            forbidden: {
                icon: "bi-shield-lock",
                title: "Access Denied",
                text: "You don't have permission to access this resource.",
            },
            unexpected: {
                icon: status === 429 ? "bi-hourglass-split" : "bi-exclamation-triangle",
                title: status === 429 ? "Too Many Requests" : "Something Went Wrong",
                text:
                    status === 429
                        ? "You've made too many requests. Please wait a moment and try again."
                        : "An unexpected error occurred. Please try again.",
            },
        }[kind],
    );

    // SvelteKit's own wording only repeats the status: it says nothing the
    // title doesn't already.
    const detail = $derived(
        message && !["Not Found", "Internal Error"].includes(message) ? message : null,
    );
</script>

<div class="row justify-content-center">
    <div class="col-xl-10">
        <div class="card rounded-4 overflow-hidden">
            <div class="row g-0">
                <div
                    class="col-md-5 d-flex align-items-center justify-content-center p-4 bg-body-secondary"
                    aria-hidden="true"
                >
                    <div
                        class="d-inline-flex p-4 p-md-5 rounded-5 bg-body border border-primary-subtle text-primary"
                    >
                        <i class="bi {content.icon} display-1 lh-1"></i>
                    </div>
                </div>

                <div class="col-md-7 d-flex flex-column justify-content-center p-4 p-md-5">
                    <p class="display-1 fw-bold text-primary mb-0" aria-hidden="true">{status}</p>
                    <h1 class="h2 mb-3">{content.title}</h1>
                    <p class="lead text-body-secondary">{content.text}</p>

                    {#if detail}
                        <div
                            class="alert alert-danger d-flex gap-2 align-items-baseline text-break mb-0"
                        >
                            <i class="bi bi-info-circle flex-shrink-0"></i>
                            <span>{detail}</span>
                        </div>
                    {/if}

                    {#if actions || showActions}
                        <div class="d-flex flex-wrap gap-2 mt-4">
                            {@render actions?.()}
                            {#if showActions}
                                <a
                                    href={resolve("/")}
                                    class="btn {actions ? 'btn-outline-primary' : 'btn-primary'}"
                                >
                                    <i class="bi bi-house-door me-1"></i>
                                    Go Home
                                </a>
                                {#if canGoBack}
                                    <button
                                        type="button"
                                        class="btn btn-outline-secondary"
                                        onclick={() => window.history.back()}
                                    >
                                        <i class="bi bi-arrow-left me-1"></i>
                                        Go Back
                                    </button>
                                {/if}
                            {/if}
                        </div>
                    {/if}

                    <details class="mt-4">
                        <summary class="text-body-secondary small">Technical details</summary>
                        <dl class="row g-0 small bg-body-tertiary rounded p-3 mt-2 mb-0">
                            <dt class="col-sm-3 fw-normal text-body-secondary">Status</dt>
                            <dd class="col-sm-9 font-monospace text-break">{status}</dd>
                            <dt class="col-sm-3 fw-normal text-body-secondary">Route</dt>
                            <dd class="col-sm-9 font-monospace text-break">
                                {page.route.id ?? "?"}
                            </dd>
                            {#if message}
                                <dt class="col-sm-3 fw-normal text-body-secondary">Message</dt>
                                <dd class="col-sm-9 font-monospace text-break">{message}</dd>
                            {/if}
                            <dt class="col-sm-3 fw-normal text-body-secondary">Time</dt>
                            <dd class="col-sm-9 font-monospace text-break mb-0">
                                {occurredAt.toISOString()}
                            </dd>
                        </dl>
                    </details>
                </div>
            </div>
        </div>
    </div>
</div>
