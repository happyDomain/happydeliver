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
                            {hop.reverse || '-'} <span class="text-muted">({hop.ip})</span> → {hop.by || 'Unknown'}
                        </h6>
                        <small class="text-muted" title={hop.timestamp}>{hop.timestamp ? new Intl.DateTimeFormat('default', { dateStyle: 'long', 'timeStyle': 'short' }).format(new Date(hop.timestamp)) : '-'}</small>
                    </div>
                    {#if hop.with || hop.id}
                        <p class="mb-1 small">
                            {#if hop.with}
                                <span class="text-muted">Protocol:</span> <code>{hop.with}</code>
                            {/if}
                            {#if hop.id}
                                <span class="text-muted ms-3">ID:</span> <code>{hop.id}</code>
                            {/if}
                            {#if hop.from}
                                <span class="text-muted ms-3">Helo:</span> <code>{hop.from}</code>
                            {/if}
                        </p>
                    {/if}
                </div>
            {/each}
        </div>
    </div>
{/if}
