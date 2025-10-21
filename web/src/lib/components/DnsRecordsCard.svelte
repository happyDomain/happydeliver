<script lang="ts">
    import type { DNSRecord } from "$lib/api/types.gen";

    interface Props {
        dnsRecords: DNSRecord[];
    }

    let { dnsRecords }: Props = $props();
</script>

<div class="card shadow-sm">
    <div class="card-header bg-white">
        <h4 class="mb-0">
            <i class="bi bi-diagram-3 me-2"></i>
            DNS Records
        </h4>
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-sm">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Value</th>
                    </tr>
                </thead>
                <tbody>
                    {#each dnsRecords as record}
                        <tr>
                            <td><code>{record.domain}</code></td>
                            <td><span class="badge bg-secondary">{record.record_type}</span></td>
                            <td>
                                <span class="badge {record.status === 'found' ? 'bg-success' : record.status === 'missing' ? 'bg-danger' : 'bg-warning'}">
                                    {record.status}
                                </span>
                            </td>
                            <td><small class="text-muted">{record.value || '-'}</small></td>
                        </tr>
                    {/each}
                </tbody>
            </table>
        </div>
    </div>
</div>
