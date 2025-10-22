<script lang="ts">
    import type { DNSResults } from "$lib/api/types.gen";

    interface Props {
        dnsResults?: DNSResults;
        dnsScore?: number;
    }

    let { dnsResults, dnsScore }: Props = $props();
</script>

<div class="card shadow-sm">
    <div class="card-header bg-white">
        <h4 class="mb-0 d-flex justify-content-between align-items-center">
            <span>
                <i class="bi bi-diagram-3 me-2"></i>
                DNS Records
            </span>
            {#if dnsScore !== undefined}
                <span class="badge bg-secondary">
                    {dnsScore}%
                </span>
            {/if}
        </h4>
    </div>
    <div class="card-body">
        {#if !dnsResults}
            <p class="text-muted mb-0">No DNS results available</p>
        {:else}
            <div class="mb-3">
                <strong>Domain:</strong> <code>{dnsResults.domain}</code>
            </div>

            {#if dnsResults.errors && dnsResults.errors.length > 0}
                <div class="alert alert-warning mb-3">
                    <strong>Errors:</strong>
                    <ul class="mb-0">
                        {#each dnsResults.errors as error}
                            <li>{error}</li>
                        {/each}
                    </ul>
                </div>
            {/if}

            <!-- MX Records -->
            {#if dnsResults.mx_records && dnsResults.mx_records.length > 0}
                <div class="mb-4">
                    <h5 class="text-muted mb-2">
                        <span class="badge bg-secondary">MX</span> Mail Exchange Records
                    </h5>
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
                                {#each dnsResults.mx_records as mx}
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
            {/if}

            <!-- SPF Record -->
            {#if dnsResults.spf_record}
                <div class="mb-4">
                    <h5 class="text-muted mb-2">
                        <span class="badge bg-secondary">SPF</span> Sender Policy Framework
                    </h5>
                    <div class="card">
                        <div class="card-body">
                            <div class="mb-2">
                                <strong>Status:</strong>
                                {#if dnsResults.spf_record.valid}
                                    <span class="badge bg-success">Valid</span>
                                {:else}
                                    <span class="badge bg-danger">Invalid</span>
                                {/if}
                            </div>
                            {#if dnsResults.spf_record.record}
                                <div class="mb-2">
                                    <strong>Record:</strong><br>
                                    <code class="d-block mt-1 text-break">{dnsResults.spf_record.record}</code>
                                </div>
                            {/if}
                            {#if dnsResults.spf_record.error}
                                <div class="text-danger">
                                    <strong>Error:</strong> {dnsResults.spf_record.error}
                                </div>
                            {/if}
                        </div>
                    </div>
                </div>
            {/if}

            <!-- DKIM Records -->
            {#if dnsResults.dkim_records && dnsResults.dkim_records.length > 0}
                <div class="mb-4">
                    <h5 class="text-muted mb-2">
                        <span class="badge bg-secondary">DKIM</span> DomainKeys Identified Mail
                    </h5>
                    {#each dnsResults.dkim_records as dkim}
                        <div class="card mb-2">
                            <div class="card-body">
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
                                        <code class="d-block mt-1 text-break small">{dkim.record}</code>
                                    </div>
                                {/if}
                                {#if dkim.error}
                                    <div class="text-danger">
                                        <strong>Error:</strong> {dkim.error}
                                    </div>
                                {/if}
                            </div>
                        </div>
                    {/each}
                </div>
            {/if}

            <!-- DMARC Record -->
            {#if dnsResults.dmarc_record}
                <div class="mb-4">
                    <h5 class="text-muted mb-2">
                        <span class="badge bg-secondary">DMARC</span> Domain-based Message Authentication
                    </h5>
                    <div class="card">
                        <div class="card-body">
                            <div class="mb-2">
                                <strong>Status:</strong>
                                {#if dnsResults.dmarc_record.valid}
                                    <span class="badge bg-success">Valid</span>
                                {:else}
                                    <span class="badge bg-danger">Invalid</span>
                                {/if}
                            </div>
                            {#if dnsResults.dmarc_record.policy}
                                <div class="mb-2">
                                    <strong>Policy:</strong>
                                    <span class="badge {dnsResults.dmarc_record.policy === 'reject' ? 'bg-success' : dnsResults.dmarc_record.policy === 'quarantine' ? 'bg-warning' : 'bg-secondary'}">
                                        {dnsResults.dmarc_record.policy}
                                    </span>
                                </div>
                            {/if}
                            {#if dnsResults.dmarc_record.record}
                                <div class="mb-2">
                                    <strong>Record:</strong><br>
                                    <code class="d-block mt-1 text-break">{dnsResults.dmarc_record.record}</code>
                                </div>
                            {/if}
                            {#if dnsResults.dmarc_record.error}
                                <div class="text-danger">
                                    <strong>Error:</strong> {dnsResults.dmarc_record.error}
                                </div>
                            {/if}
                        </div>
                    </div>
                </div>
            {/if}

            <!-- BIMI Record -->
            {#if dnsResults.bimi_record}
                <div class="mb-4">
                    <h5 class="text-muted mb-2">
                        <span class="badge bg-secondary">BIMI</span> Brand Indicators for Message Identification
                    </h5>
                    <div class="card">
                        <div class="card-body">
                            <div class="mb-2">
                                <strong>Selector:</strong> <code>{dnsResults.bimi_record.selector}</code>
                                <strong class="ms-3">Domain:</strong> <code>{dnsResults.bimi_record.domain}</code>
                            </div>
                            <div class="mb-2">
                                <strong>Status:</strong>
                                {#if dnsResults.bimi_record.valid}
                                    <span class="badge bg-success">Valid</span>
                                {:else}
                                    <span class="badge bg-danger">Invalid</span>
                                {/if}
                            </div>
                            {#if dnsResults.bimi_record.logo_url}
                                <div class="mb-2">
                                    <strong>Logo URL:</strong> <a href={dnsResults.bimi_record.logo_url} target="_blank" rel="noopener noreferrer">{dnsResults.bimi_record.logo_url}</a>
                                </div>
                            {/if}
                            {#if dnsResults.bimi_record.vmc_url}
                                <div class="mb-2">
                                    <strong>VMC URL:</strong> <a href={dnsResults.bimi_record.vmc_url} target="_blank" rel="noopener noreferrer">{dnsResults.bimi_record.vmc_url}</a>
                                </div>
                            {/if}
                            {#if dnsResults.bimi_record.record}
                                <div class="mb-2">
                                    <strong>Record:</strong><br>
                                    <code class="d-block mt-1 text-break">{dnsResults.bimi_record.record}</code>
                                </div>
                            {/if}
                            {#if dnsResults.bimi_record.error}
                                <div class="text-danger">
                                    <strong>Error:</strong> {dnsResults.bimi_record.error}
                                </div>
                            {/if}
                        </div>
                    </div>
                </div>
            {/if}
        {/if}
    </div>
</div>
