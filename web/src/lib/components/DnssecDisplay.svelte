<script lang="ts">
    interface Props {
        dnssecEnabled?: boolean;
        domain?: string;
    }

    let { dnssecEnabled, domain }: Props = $props();

    // DNSSEC is valid if it's explicitly enabled
    const dnssecIsValid = $derived(dnssecEnabled === true);
</script>

{#if dnssecEnabled !== undefined}
    <div class="card mb-4" id="dns-dnssec">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="text-muted mb-0">
                <i
                    class="bi"
                    class:bi-shield-check={dnssecIsValid}
                    class:text-success={dnssecIsValid}
                    class:bi-shield-x={!dnssecIsValid}
                    class:text-warning={!dnssecIsValid}
                ></i>
                DNSSEC
            </h5>
            <span class="badge bg-secondary">Security</span>
        </div>
        <div class="card-body">
            <p class="card-text small text-muted mb-3">
                DNSSEC (DNS Security Extensions) adds cryptographic signatures to DNS records to verify
                their authenticity and integrity. It protects against DNS spoofing and cache poisoning
                attacks, ensuring that DNS responses haven't been tampered with.
            </p>
            {#if domain}
                <div class="mb-2">
                    <strong>Domain:</strong> <code>{domain}</code>
                </div>
            {/if}
            {#if dnssecIsValid}
                <div class="alert alert-success mb-0">
                    <i class="bi bi-check-circle me-1"></i>
                    <strong>Enabled:</strong> DNSSEC is properly configured with a valid chain of trust.
                    This provides additional security and authenticity for your domain's DNS records.
                </div>
            {:else}
                <div class="alert alert-warning mb-0">
                    <i class="bi bi-info-circle me-1"></i>
                    <strong>Not Enabled:</strong> DNSSEC is not configured for this domain. While not
                    required for email delivery, enabling DNSSEC provides additional security by protecting
                    against DNS-based attacks. Consider enabling DNSSEC through your domain registrar or
                    DNS provider.
                </div>
            {/if}
        </div>
    </div>
{/if}
