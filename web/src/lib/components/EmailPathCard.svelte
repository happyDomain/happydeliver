<script lang="ts">
    import type { ReceivedHop } from "$lib/api/types.gen";

    interface Props {
        receivedChain: ReceivedHop[];
    }

    let { receivedChain }: Props = $props();
</script>

{#if receivedChain && receivedChain.length > 0}
    <div class="mb-3" id="email-path">
        <h5>Email Path (Received Chain)</h5>
        <div class="list-group">
            {#each receivedChain as hop, i}
                <div class="list-group-item">
                    <div class="d-flex w-100 justify-content-between">
                        <h6 class="mb-1">
                            <span class="badge bg-primary me-2">{receivedChain.length - i}</span>
                            {hop.reverse || "-"}
                            {#if hop.ip}<span class="text-muted">({hop.ip})</span>{/if} → {hop.by ||
                                "Unknown"}
                        </h6>
                        <small class="text-muted" title={hop.timestamp}>
                            {hop.timestamp
                                ? new Intl.DateTimeFormat("default", {
                                      dateStyle: "long",
                                      timeStyle: "short",
                                  }).format(new Date(hop.timestamp))
                                : "-"}
                        </small>
                    </div>
                    {#if hop.with || hop.id}
                        <p class="mb-1 small d-flex gap-3">
                            {#if hop.with}
                                <span>
                                    <span class="text-muted">Protocol:</span>
                                    <code>{hop.with}</code>
                                </span>
                            {/if}
                            {#if hop.id}
                                <span>
                                    <span class="text-muted">ID:</span> <code>{hop.id}</code>
                                </span>
                            {/if}
                            {#if hop.from}
                                <span>
                                    <span class="text-muted">Helo:</span> <code>{hop.from}</code>
                                </span>
                            {/if}
                        </p>
                    {/if}
                </div>
            {/each}
        </div>
    </div>
{/if}
