<script lang="ts">
    import type { ClassValue } from 'svelte/elements';
    import type { MXRecord } from "$lib/api/types.gen";

    interface Props {
        class: ClassValue;
        mxRecords: MXRecord[];
        title: string;
        description?: string;
    }

    let { class: className, mxRecords, title, description }: Props = $props();

    let mxsAreValids = $derived(mxRecords.reduce((acc, r) => acc && r.valid, true));
</script>

<div class="card {className}">
    <div class="card-header d-flex justify-content-between align-items-center">
        <h5 class="text-muted mb-0">
            <i
                class="bi"
                class:bi-check-circle-fill={mxsAreValids}
                class:text-success={mxsAreValids}
                class:bi-x-circle-fill={!mxsAreValids}
                class:text-danger={!mxsAreValids}
            ></i>
            {title}
        </h5>
        <span class="badge bg-secondary">MX</span>
    </div>
    <div class="card-body">
        {#if description}
            <p class="card-text small text-muted mb-0">{description}</p>
        {/if}
    </div>
    <div class="list-group list-group-flush">
        {#each mxRecords as mx}
            <div class="list-group-item">
                <div class="d-flex gap-2 align-items-center">
                    {#if mx.valid}
                        <span class="badge bg-success">Valid</span>
                    {:else}
                        <span class="badge bg-danger">Invalid</span>
                    {/if}
                    <div>Host: <code>{mx.host}</code></div>
                    <div>Priority: <strong>{mx.priority}</strong></div>
                </div>
                {#if mx.error}
                    <small class="text-danger">{mx.error}</small>
                {/if}
            </div>
        {/each}
    </div>
</div>
