<script lang="ts">
    import type { SPFRecord } from "$lib/api/types.gen";

    interface Props {
        spfRecords?: SPFRecord[];
    }

    let { spfRecords }: Props = $props();

    // Compute overall validity
    const spfIsValid = $derived(
        spfRecords?.reduce((acc, r) => acc && r.valid, true) ?? false
    );
</script>

{#if spfRecords && spfRecords.length > 0}
    <div class="card mb-4">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="text-muted mb-2">
                <i
                    class="bi"
                    class:bi-check-circle-fill={spfIsValid}
                    class:text-success={spfIsValid}
                    class:bi-x-circle-fill={!spfIsValid}
                    class:text-danger={!spfIsValid}
                ></i>
                Sender Policy Framework
            </h5>
            <span class="badge bg-secondary">SPF</span>
        </div>
        <div class="card-body">
            <p class="card-text small text-muted mb-0">SPF specifies which mail servers are authorized to send emails on behalf of your domain. Receiving servers check the sender's IP address against your SPF record to prevent email spoofing.</p>
        </div>
        <div class="list-group list-group-flush">
            {#each spfRecords as spf, index}
                <div class="list-group-item">
                    {#if spf.domain}
                        <div class="mb-2">
                            <strong>Domain:</strong> <code>{spf.domain}</code>
                            {#if index > 0}
                                <span class="badge bg-info ms-2">Included</span>
                            {/if}
                        </div>
                    {/if}
                    <div class="mb-2">
                        <strong>Status:</strong>
                        {#if spf.valid}
                            <span class="badge bg-success">Valid</span>
                        {:else}
                            <span class="badge bg-danger">Invalid</span>
                        {/if}
                    </div>
                    {#if spf.record}
                        <div class="mb-2">
                            <strong>Record:</strong><br>
                            <code class="d-block mt-1 text-break">{spf.record}</code>
                        </div>
                    {/if}
                    {#if spf.error}
                        <div class="alert alert-{spf.valid ? 'warning' : 'danger'} mb-0 mt-2">
                            <i class="bi bi-{spf.valid ? 'exclamation-triangle' : 'x-circle'} me-1"></i>
                            <strong>{spf.valid ? 'Warning:' : 'Error:'}</strong> {spf.error}
                        </div>
                    {/if}
                </div>
            {/each}
        </div>
    </div>
{/if}
