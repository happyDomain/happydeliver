<script lang="ts">
    import { createEventDispatcher } from "svelte";

    import type { Test } from "$lib/api/types.gen";
    import EmailAddressDisplay from "./EmailAddressDisplay.svelte";

    const dispatch = createEventDispatcher();

    interface Props {
        test: Test;
        fetching?: boolean;
    }

    let { test, nbfetch, nextfetch, fetching = false }: Props = $props();

    let lastForcedCheck = $state(Date.now() - 12345);
    function forceCheck() {
        lastForcedCheck = Date.now();
        dispatch("force-inbox-check");
    }
</script>

<div class="row justify-content-center">
    <div class="col-lg-8 fade-in">
        <div class="card shadow-lg">
            <div class="card-body p-5 text-center">
                <div class="pulse mb-4">
                    <i class="bi bi-envelope-paper display-1 text-primary"></i>
                </div>

                <h2 class="fw-bold mb-3">Waiting for Your Email</h2>
                <p class="text-muted mb-4">Send your test email to the address below:</p>

                <div class="mb-4">
                    <EmailAddressDisplay email={test.email} />
                </div>

                <div class="alert alert-info mb-4" role="alert">
                    <i class="bi bi-lightbulb me-2"></i>
                    {#if nbfetch > 4}
                        <strong>Tip:</strong> Check your mail is not stuck in the sending box.
                    {:else}
                        <strong>Tip:</strong> Send an email that represents your actual use case (newsletters,
                        transactional emails, etc.) for the most accurate results.
                    {/if}
                </div>

                <div class="d-flex align-items-center justify-content-center gap-2 text-muted">
                    <div class="spinner-border spinner-border-sm" role="status"></div>
                    {#if fetching || nextfetch === 0}
                        <small>Looking for new email...</small>
                    {:else if nextfetch}
                        <div>
                            <small>
                                Next inbox check in {nextfetch} second{#if nextfetch > 1}s{/if}...
                            </small>
                            {#if nbfetch > 0}
                                <button
                                    type="button"
                                    class="btn btn-sm btn-link"
                                    onclick={forceCheck}
                                    disabled={nbfetch + Date.now() < lastForcedCheck + 10000}
                                >
                                    <i class="bi bi-mailbox me-1"></i>Check now
                                </button>
                            {/if}
                        </div>
                    {:else}
                        <small>Checking for email every 3 seconds...</small>
                    {/if}
                </div>
            </div>
        </div>

        <!-- Instructions Card -->
        <div class="card mt-4">
            <div class="card-body">
                <h5 class="fw-bold mb-3">
                    <i class="bi bi-info-circle me-2"></i>What we'll check:
                </h5>
                <div class="row">
                    <div class="col-md-6">
                        <ul class="list-unstyled mb-0">
                            <li class="mb-2">
                                <i class="bi bi-check2 text-success me-2"></i> SPF, DKIM, DMARC, BIMI
                            </li>
                            <li class="mb-2">
                                <i class="bi bi-check2 text-success me-2"></i> DNS Records
                            </li>
                            <li class="mb-2">
                                <i class="bi bi-check2 text-success me-2"></i> SpamAssassin Score
                            </li>
                        </ul>
                    </div>
                    <div class="col-md-6">
                        <ul class="list-unstyled mb-0">
                            <li class="mb-2">
                                <i class="bi bi-check2 text-success me-2"></i> Blacklist Status
                            </li>
                            <li class="mb-2">
                                <i class="bi bi-check2 text-success me-2"></i> Content Quality
                            </li>
                            <li class="mb-2">
                                <i class="bi bi-check2 text-success me-2"></i> Header Validation
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
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

    .pulse {
        animation: pulse 2s ease-in-out infinite;
    }

    @keyframes pulse {
        0%,
        100% {
            opacity: 1;
        }
        50% {
            opacity: 0.5;
        }
    }
</style>
