<script lang="ts">
    import type { HeaderAnalysis } from "$lib/api/types.gen";

    interface Props {
        headerAnalysis: HeaderAnalysis;
        headerScore?: number;
    }

    let { headerAnalysis, headerScore }: Props = $props();
</script>

<div class="card shadow-sm">
    <div class="card-header bg-white">
        <h4 class="mb-0 d-flex justify-content-between align-items-center">
            <span>
                <i class="bi bi-list-ul me-2"></i>
                Header Analysis
            </span>
            {#if headerScore !== undefined}
                <span class="badge bg-secondary">
                    {headerScore}%
                </span>
            {/if}
        </h4>
    </div>
    <div class="card-body">
        {#if headerAnalysis.issues && headerAnalysis.issues.length > 0}
            <div class="mb-3">
                <h6>Issues</h6>
                {#each headerAnalysis.issues as issue}
                    <div class="alert alert-{issue.severity === 'critical' || issue.severity === 'high' ? 'danger' : issue.severity === 'medium' ? 'warning' : 'info'} py-2 px-3 mb-2">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <strong>{issue.header}</strong>
                                <div class="small">{issue.message}</div>
                                {#if issue.advice}
                                    <div class="small mt-1">
                                        <i class="bi bi-lightbulb me-1"></i>
                                        {issue.advice}
                                    </div>
                                {/if}
                            </div>
                            <span class="badge bg-secondary">{issue.severity}</span>
                        </div>
                    </div>
                {/each}
            </div>
        {/if}

        {#if headerAnalysis.domain_alignment}
            <div class="mb-3">
                <h6>Domain Alignment</h6>
                <div class="card">
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-4">
                                <small class="text-muted">From Domain</small>
                                <div><code>{headerAnalysis.domain_alignment.from_domain || '-'}</code></div>
                            </div>
                            <div class="col-md-4">
                                <small class="text-muted">Return-Path Domain</small>
                                <div><code>{headerAnalysis.domain_alignment.return_path_domain || '-'}</code></div>
                            </div>
                            <div class="col-md-4">
                                <small class="text-muted">Aligned</small>
                                <div>
                                    <i class="bi {headerAnalysis.domain_alignment.aligned ? 'bi-check-circle text-success' : 'bi-x-circle text-danger'} me-1"></i>
                                    {headerAnalysis.domain_alignment.aligned ? 'Yes' : 'No'}
                                </div>
                            </div>
                        </div>
                        {#if headerAnalysis.domain_alignment.issues && headerAnalysis.domain_alignment.issues.length > 0}
                            <div class="mt-2">
                                {#each headerAnalysis.domain_alignment.issues as issue}
                                    <div class="text-warning small">
                                        <i class="bi bi-exclamation-triangle me-1"></i>
                                        {issue}
                                    </div>
                                {/each}
                            </div>
                        {/if}
                    </div>
                </div>
            </div>
        {/if}

        {#if headerAnalysis.headers && Object.keys(headerAnalysis.headers).length > 0}
            <div class="mt-3">
                <h6>Headers</h6>
                <div class="table-responsive">
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>Header</th>
                                <th>Present</th>
                                <th>Valid</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            {#each Object.entries(headerAnalysis.headers).sort((a, b) => {
                                const importanceOrder = { 'required': 0, 'recommended': 1, 'optional': 2, 'newsletter': 3 };
                                const aImportance = importanceOrder[a[1].importance || 'optional'];
                                const bImportance = importanceOrder[b[1].importance || 'optional'];
                                return aImportance - bImportance;
                            }) as [name, check]}
                                <tr>
                                    <td>
                                        <code>{name}</code>
                                        {#if check.importance}
                                            <span class="badge bg-{check.importance === 'required' ? 'danger' : check.importance === 'recommended' ? 'warning' : 'secondary'} ms-1">
                                                {check.importance}
                                            </span>
                                        {/if}
                                    </td>
                                    <td>
                                        <i class="bi {check.present ? 'bi-check-circle text-success' : 'bi-x-circle text-danger'}"></i>
                                    </td>
                                    <td>
                                        {#if check.present && check.valid !== undefined}
                                            <i class="bi {check.valid ? 'bi-check-circle text-success' : 'bi-x-circle text-warning'}"></i>
                                        {:else}
                                            -
                                        {/if}
                                    </td>
                                    <td>
                                        <small class="text-muted text-break">{check.value || '-'}</small>
                                        {#if check.issues && check.issues.length > 0}
                                            {#each check.issues as issue}
                                                <div class="text-warning small">
                                                    <i class="bi bi-exclamation-triangle me-1"></i>
                                                    {issue}
                                                </div>
                                            {/each}
                                        {/if}
                                    </td>
                                </tr>
                            {/each}
                        </tbody>
                    </table>
                </div>
            </div>
        {/if}

        {#if headerAnalysis.received_chain && headerAnalysis.received_chain.length > 0}
            <div class="mt-3">
                <h6>Email Path (Received Chain)</h6>
                <div class="list-group">
                    {#each headerAnalysis.received_chain as hop, i}
                        <div class="list-group-item">
                            <div class="d-flex w-100 justify-content-between">
                                <h6 class="mb-1">
                                    <span class="badge bg-primary me-2">{i + 1}</span>
                                    {hop.from || 'Unknown'} → {hop.by || 'Unknown'}
                                </h6>
                                <small class="text-muted">{hop.timestamp || '-'}</small>
                            </div>
                            {#if hop.with || hop.id}
                                <p class="mb-1 small">
                                    {#if hop.with}
                                        <span class="text-muted">Protocol:</span> <code>{hop.with}</code>
                                    {/if}
                                    {#if hop.id}
                                        <span class="text-muted ms-3">ID:</span> <code>{hop.id}</code>
                                    {/if}
                                </p>
                            {/if}
                        </div>
                    {/each}
                </div>
            </div>
        {/if}
    </div>
</div>
