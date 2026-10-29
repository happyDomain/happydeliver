<script lang="ts">
    import type { Issue } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        ptrRecords?: string[];
        ptrForwardRecords?: string[];
        senderIp?: string;
        issues?: Issue[];
    }

    let { ptrRecords, ptrForwardRecords, senderIp, issues }: Props = $props();

    // Confirmed when one of the addresses the PTR hostname resolves to is the sender's.
    const confirmed = $derived(!!senderIp && (ptrForwardRecords ?? []).includes(senderIp));
    const forward = $derived(ptrForwardRecords ?? []);

    let showDifferent = $state(false);
    const differentCount = $derived(forward.filter((ip) => ip !== senderIp).length);
</script>

{#if ptrRecords && ptrRecords.length > 0}
    <CheckCard
        id="dns-fcrdns"
        title="Forward-Confirmed Reverse DNS"
        tag="FCrDNS"
        status={confirmed ? "pass" : "warn"}
        summary={confirmed
            ? `${ptrRecords[0]} → ${senderIp}`
            : forward.length > 0
              ? `${ptrRecords[0]} → ${forward.join(", ")}`
              : `${ptrRecords[0]} does not resolve`}
        docs={[docs.reverseDns]}
        {issues}
    >
        <div class="card-body">
            <dl class="check-facts">
                <dt>PTR</dt>
                <dd>
                    {#each ptrRecords as ptr, i (i)}
                        <code class="d-block">{ptr}</code>
                    {/each}
                </dd>
                <dt>Resolves to</dt>
                <dd>
                    {#each forward as ip, j (j)}
                        {#if ip === senderIp || !confirmed || showDifferent}
                            <div>
                                <code>{ip}</code>
                                {#if ip === senderIp}
                                    <span class="small text-success ms-1">sender IP</span>
                                {:else if !confirmed}
                                    <span class="small text-body-secondary ms-1"
                                        >not {senderIp ?? "the sender IP"}</span
                                    >
                                {/if}
                            </div>
                        {/if}
                    {:else}
                        no A or AAAA record
                    {/each}
                    {#if confirmed && differentCount > 0}
                        <button
                            class="btn btn-link btn-sm p-0 text-muted"
                            onclick={() => (showDifferent = !showDifferent)}
                        >
                            {#if showDifferent}
                                Hide other IPs
                            {:else}
                                Show {differentCount} other IP{differentCount > 1 ? "s" : ""}
                            {/if}
                        </button>
                    {/if}
                </dd>
            </dl>
            <p class="check-about">
                Forward-confirmed reverse DNS checks that the PTR hostname resolves back to the
                sending IP: anyone can set a PTR record to any name, only the owner of that name can
                make it point back.
            </p>
        </div>
    </CheckCard>
{/if}
