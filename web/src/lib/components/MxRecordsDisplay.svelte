<script lang="ts">
    import type { ClassValue } from "svelte/elements";

    import type { MxRecord } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        id?: string;
        class: ClassValue;
        mxRecords: MxRecord[];
        title: string;
        description?: string;
    }

    let { id, class: className, mxRecords, title, description }: Props = $props();

    let mxsAreValids = $derived(mxRecords.reduce((acc, r) => acc && r.valid, true));
</script>

<CheckCard
    {id}
    class={className}
    {title}
    tag="MX"
    status={mxsAreValids ? "pass" : "fail"}
    summary={mxRecords.map((mx) => mx.host).join(", ")}
    docs={[docs.mxLookup]}
>
    <div class="card-body">
        {#if description}
            <p class="card-text small text-muted mb-0">{description}</p>
        {/if}
    </div>
    <div class="list-group list-group-flush">
        {#each mxRecords as mx, i (i)}
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
</CheckCard>
