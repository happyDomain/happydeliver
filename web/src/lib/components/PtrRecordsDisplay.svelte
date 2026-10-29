<script lang="ts">
    import type { Issue } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        ptrRecords?: string[];
        senderIp?: string;
        issues?: Issue[];
    }

    let { ptrRecords, senderIp, issues }: Props = $props();

    const found = $derived(ptrRecords && ptrRecords.length > 0);
</script>

{#if found || senderIp}
    <CheckCard
        id="dns-ptr"
        title="Reverse DNS"
        tag="PTR"
        status={!found ? "fail" : ptrRecords!.length > 1 ? "warn" : "pass"}
        summary={found ? ptrRecords!.join(", ") : `No PTR record for ${senderIp}`}
        docs={[docs.reverseDns]}
        {issues}
    >
        <div class="card-body">
            <dl class="check-facts">
                {#if senderIp}
                    <dt>Sender IP</dt>
                    <dd><span class="font-monospace">{senderIp}</span></dd>
                {/if}
                <dt>PTR</dt>
                <dd>
                    {#each ptrRecords ?? [] as ptr, i (i)}
                        <span class="font-monospace d-block">{ptr}</span>
                    {:else}
                        none
                    {/each}
                </dd>
            </dl>
            <p class="check-about">
                A PTR record, or reverse DNS, maps the sending IP address back to a hostname. Many
                receivers check that the sending IP has one, and expect exactly one.
            </p>
        </div>
    </CheckCard>
{/if}
