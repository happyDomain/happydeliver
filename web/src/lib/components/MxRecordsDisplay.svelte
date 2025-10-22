<script lang="ts">
    import type { MXRecord } from "$lib/api/types.gen";

    interface Props {
        mxRecords: MXRecord[];
        title: string;
        description?: string;
    }

    let { mxRecords, title, description }: Props = $props();
</script>

<div class="mb-4">
    <h5 class="text-muted mb-2">
        <span class="badge bg-secondary">MX</span> {title}
    </h5>
    {#if description}
        <p class="small text-muted mb-2">{description}</p>
    {/if}
    <div class="table-responsive">
        <table class="table table-sm table-bordered">
            <thead>
                <tr>
                    <th>Priority</th>
                    <th>Host</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {#each mxRecords as mx}
                    <tr>
                        <td>{mx.priority}</td>
                        <td><code>{mx.host}</code></td>
                        <td>
                            {#if mx.valid}
                                <span class="badge bg-success">Valid</span>
                            {:else}
                                <span class="badge bg-danger">Invalid</span>
                                {#if mx.error}
                                    <br><small class="text-danger">{mx.error}</small>
                                {/if}
                            {/if}
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
</div>
