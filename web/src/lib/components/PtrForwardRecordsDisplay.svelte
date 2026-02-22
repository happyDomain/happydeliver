<script lang="ts">
    interface Props {
        ptrRecords?: string[];
        ptrForwardRecords?: string[];
        senderIp?: string;
    }

    let { ptrRecords, ptrForwardRecords, senderIp }: Props = $props();

    // Forward-confirmed reverse DNS is valid if:
    // 1. PTR records exist
    // 2. Forward records exist
    // 3. At least one forward record matches the original sender IP
    const fcrDnsIsValid = $derived(
        ptrRecords &&
            ptrRecords.length > 0 &&
            ptrForwardRecords &&
            ptrForwardRecords.length > 0 &&
            senderIp &&
            ptrForwardRecords.includes(senderIp),
    );

    const hasForwardRecords = $derived(ptrForwardRecords && ptrForwardRecords.length > 0);

    let showDifferent = $state(false);
    const differentCount = $derived(
        ptrForwardRecords ? ptrForwardRecords.filter((ip) => ip !== senderIp).length : 0,
    );
</script>

{#if ptrRecords && ptrRecords.length > 0}
    <div class="card mb-4">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="text-muted mb-0">
                <i
                    class="bi"
                    class:bi-check-circle-fill={fcrDnsIsValid}
                    class:text-success={fcrDnsIsValid}
                    class:bi-x-circle-fill={!fcrDnsIsValid}
                    class:text-danger={!fcrDnsIsValid}
                ></i>
                Forward-Confirmed Reverse DNS
            </h5>
            <span class="badge bg-secondary">FCrDNS</span>
        </div>
        <div class="card-body">
            <p class="card-text small text-muted mb-0">
                Forward-confirmed reverse DNS (FCrDNS) verifies that the PTR hostname resolves back
                to the original sender IP. This double-check helps establish sender legitimacy.
            </p>
            {#if senderIp}
                <div class="mt-2">
                    <strong>Original Sender IP:</strong> <code>{senderIp}</code>
                </div>
            {/if}
        </div>
        {#if hasForwardRecords}
            <div class="list-group list-group-flush">
                <div class="list-group-item">
                    <div class="mb-2">
                        <strong>PTR Hostname(s):</strong>
                        {#each ptrRecords as ptr}
                            <div class="mt-1">
                                <code>{ptr}</code>
                            </div>
                        {/each}
                    </div>
                    <div class="mb-2">
                        <strong>Forward Resolution (A/AAAA):</strong>
                        {#each ptrForwardRecords as ip}
                            {#if ip === senderIp || !fcrDnsIsValid || showDifferent}
                                <div class="d-flex gap-2 align-items-center mt-1">
                                    {#if senderIp && ip === senderIp}
                                        <span class="badge bg-success">Match</span>
                                    {:else}
                                        <span class="badge bg-secondary">Different</span>
                                    {/if}
                                    <code>{ip}</code>
                                </div>
                            {/if}
                        {/each}
                        {#if fcrDnsIsValid && differentCount > 0}
                            <div class="mt-1">
                                <button
                                    class="btn btn-link btn-sm p-0 text-muted"
                                    onclick={() => (showDifferent = !showDifferent)}
                                >
                                    {#if showDifferent}
                                        Hide other IPs
                                    {:else}
                                        Show {differentCount} other IP{differentCount > 1 ? 's' : ''} (not the sender)
                                    {/if}
                                </button>
                            </div>
                        {/if}
                    </div>
                    {#if fcrDnsIsValid}
                        <div class="alert alert-success mb-0 mt-2">
                            <i class="bi bi-check-circle me-1"></i>
                            <strong>Success:</strong> Forward-confirmed reverse DNS is properly configured.
                            The PTR hostname resolves back to the sender IP.
                        </div>
                    {:else}
                        <div class="alert alert-warning mb-0 mt-2">
                            <i class="bi bi-exclamation-triangle me-1"></i>
                            <strong>Warning:</strong> The PTR hostname does not resolve back to the sender
                            IP. This may impact deliverability.
                        </div>
                    {/if}
                </div>
            </div>
        {:else}
            <div class="list-group list-group-flush">
                <div class="list-group-item">
                    <div class="alert alert-danger mb-0">
                        <i class="bi bi-x-circle me-1"></i>
                        <strong>Error:</strong> PTR hostname(s) found but could not resolve to any IP
                        addresses. Check your DNS configuration.
                    </div>
                </div>
            </div>
        {/if}
    </div>
{/if}
