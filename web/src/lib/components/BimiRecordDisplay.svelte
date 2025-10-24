<script lang="ts">
    import type { BimiRecord } from "$lib/api/types.gen";

    interface Props {
        bimiRecord?: BimiRecord;
    }

    let { bimiRecord }: Props = $props();
</script>

{#if bimiRecord}
    <div class="card mb-4" id="dns-bimi">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="text-muted mb-0">
                <i
                    class="bi"
                    class:bi-check-circle-fill={bimiRecord.valid}
                    class:text-success={bimiRecord.valid}
                    class:bi-x-circle-fill={!bimiRecord.valid}
                    class:text-danger={!bimiRecord.valid}
                ></i>
                Brand Indicators for Message Identification
            </h5>
            <span class="badge bg-secondary">BIMI</span>
        </div>
        <div class="card-body">
            <p class="card-text small text-muted mb-2">
                BIMI allows your brand logo to be displayed next to your emails in supported mail
                clients. Requires strong DMARC enforcement (quarantine or reject policy) and
                optionally a Verified Mark Certificate (VMC).
            </p>

            <hr />

            <div class="mb-2">
                <strong>Selector:</strong> <code>{bimiRecord.selector}</code>
                <strong class="ms-3">Domain:</strong> <code>{bimiRecord.domain}</code>
            </div>
            <div class="mb-2">
                <strong>Status:</strong>
                {#if bimiRecord.valid}
                    <span class="badge bg-success">Valid</span>
                {:else}
                    <span class="badge bg-danger">Invalid</span>
                {/if}
            </div>
            {#if bimiRecord.logo_url}
                <div class="mb-2">
                    <strong>Logo URL:</strong>
                    <a href={bimiRecord.logo_url} target="_blank" rel="noopener noreferrer"
                        >{bimiRecord.logo_url}</a
                    >
                </div>
            {/if}
            {#if bimiRecord.vmc_url}
                <div class="mb-2">
                    <strong>VMC URL:</strong>
                    <a href={bimiRecord.vmc_url} target="_blank" rel="noopener noreferrer"
                        >{bimiRecord.vmc_url}</a
                    >
                </div>
            {/if}
            {#if bimiRecord.record}
                <div class="mb-2">
                    <strong>Record:</strong><br />
                    <code class="d-block mt-1 text-break">{bimiRecord.record}</code>
                </div>
            {/if}
            {#if bimiRecord.error}
                <div class="text-danger">
                    <strong>Error:</strong>
                    {bimiRecord.error}
                </div>
            {/if}
        </div>
    </div>
{/if}
