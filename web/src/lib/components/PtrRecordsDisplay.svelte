<script lang="ts">
    interface Props {
        ptrRecords?: string[];
        senderIp?: string;
    }

    let { ptrRecords, senderIp }: Props = $props();

    // PTR records are valid if at least one exists
    const ptrIsValid = $derived(ptrRecords && ptrRecords.length > 0);
</script>

{#if ptrRecords && ptrRecords.length > 0}
    <div class="card mb-4" id="dns-ptr">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="text-muted mb-0">
                <i
                    class="bi"
                    class:bi-check-circle-fill={ptrIsValid}
                    class:text-success={ptrIsValid}
                    class:bi-x-circle-fill={!ptrIsValid}
                    class:text-danger={!ptrIsValid}
                ></i>
                Reverse DNS
            </h5>
            <span class="badge bg-secondary">PTR</span>
        </div>
        <div class="card-body">
            <p class="card-text small text-muted mb-0">
                PTR (pointer record), also known as reverse DNS maps IP addresses back to hostnames.
                Having proper PTR records is important as many mail servers verify that the sending
                IP has a valid reverse DNS entry.
            </p>
            {#if senderIp}
                <div class="mt-2">
                    <strong>Sender IP:</strong> <code>{senderIp}</code>
                </div>
            {/if}
        </div>
        <div class="list-group list-group-flush">
            {#each ptrRecords as ptr}
                <div class="list-group-item">
                    <div class="d-flex gap-2 align-items-center">
                        <span class="badge bg-success">Found</span>
                        <code>{ptr}</code>
                    </div>
                </div>
            {/each}
            {#if ptrRecords.length > 1}
                <div class="list-group-item">
                    <div class="alert alert-warning mb-0">
                        <i class="bi bi-exclamation-triangle me-1"></i>
                        <strong>Warning:</strong> Multiple PTR records found. While not strictly an error,
                        having multiple PTR records can cause issues with some mail servers. It's recommended
                        to have exactly one PTR record per IP address.
                    </div>
                </div>
            {/if}
        </div>
    </div>
{:else if senderIp}
    <div class="card mb-4">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="text-muted mb-2">
                <i class="bi bi-x-circle-fill text-danger"></i>
                Reverse DNS (PTR)
            </h5>
            <span class="badge bg-secondary">PTR</span>
        </div>
        <div class="card-body">
            <p class="card-text small text-muted mb-0">
                PTR records (reverse DNS) map IP addresses back to hostnames. Having proper PTR
                records is important for email deliverability.
            </p>
            <div class="mt-2">
                <strong>Sender IP:</strong> <code>{senderIp}</code>
            </div>
            <div class="alert alert-danger mb-0 mt-2">
                <i class="bi bi-x-circle me-1"></i>
                <strong>Error:</strong> No PTR records found for the sender IP. Contact your email service
                provider to configure reverse DNS.
            </div>
        </div>
    </div>
{/if}
