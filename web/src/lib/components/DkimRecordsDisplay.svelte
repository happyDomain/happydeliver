<script lang="ts">
    import type { DKIMRecord } from "$lib/api/types.gen";

    interface Props {
        dkimRecords?: DKIMRecord[];
    }

    let { dkimRecords }: Props = $props();

    // Compute overall validity
    const dkimIsValid = $derived(
        dkimRecords?.reduce((acc, r) => acc && r.valid, true) ?? false
    );
</script>

{#if dkimRecords && dkimRecords.length > 0}
    <div class="card mb-4">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="text-muted mb-0">
                <i
                    class="bi"
                    class:bi-check-circle-fill={dkimIsValid}
                    class:text-success={dkimIsValid}
                    class:bi-x-circle-fill={!dkimIsValid}
                    class:text-danger={!dkimIsValid}
                ></i>
                DomainKeys Identified Mail
            </h5>
            <span class="badge bg-secondary">DKIM</span>
        </div>
        <div class="card-body">
            <p class="card-text small text-muted mb-0">DKIM cryptographically signs your emails, proving they haven't been tampered with in transit. Receiving servers verify this signature against your DNS records.</p>
        </div>
        <div class="list-group list-group-flush">
            {#each dkimRecords as dkim}
                <div class="list-group-item">
                    <div class="mb-2">
                        <strong>Selector:</strong> <code>{dkim.selector}</code>
                        <strong class="ms-3">Domain:</strong> <code>{dkim.domain}</code>
                    </div>
                    <div class="mb-2">
                        <strong>Status:</strong>
                        {#if dkim.valid}
                            <span class="badge bg-success">Valid</span>
                        {:else}
                            <span class="badge bg-danger">Invalid</span>
                        {/if}
                    </div>
                    {#if dkim.record}
                        <div class="mb-2">
                            <strong>Record:</strong><br>
                            <code class="d-block mt-1 text-break small text-truncate">{dkim.record}</code>
                        </div>
                    {/if}
                    {#if dkim.error}
                        <div class="text-danger">
                            <strong>Error:</strong> {dkim.error}
                        </div>
                    {/if}
                </div>
            {/each}
        </div>
    </div>
{/if}
