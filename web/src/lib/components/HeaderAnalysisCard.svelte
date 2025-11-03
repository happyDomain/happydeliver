<script lang="ts">
    import type { AuthResult, DmarcRecord, HeaderAnalysis } from "$lib/api/types.gen";
    import { getScoreColorClass } from "$lib/score";
    import { theme } from "$lib/stores/theme";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        dmarcRecord?: DmarcRecord;
        headerAnalysis: HeaderAnalysis;
        headerGrade?: string;
        headerScore?: number;
    }

    let { dmarcRecord, headerAnalysis, headerGrade, headerScore, xAlignedFrom }: Props = $props();
</script>

<div class="card shadow-sm" id="header-details">
    <div class="card-header {$theme === 'light' ? 'bg-white' : 'bg-dark'}">
        <h4 class="mb-0 d-flex justify-content-between align-items-center">
            <span>
                <i class="bi bi-list-ul me-2"></i>
                Header Analysis
            </span>
            <span>
                {#if headerScore !== undefined}
                    <span class="badge bg-{getScoreColorClass(headerScore)}">
                        {headerScore}%
                    </span>
                {/if}
                {#if headerGrade !== undefined}
                    <GradeDisplay grade={headerGrade} size="small" />
                {/if}
            </span>
        </h4>
    </div>
    <div class="card-body">
        {#if headerAnalysis.issues && headerAnalysis.issues.length > 0}
            <div class="mb-3">
                <h5>Issues</h5>
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
            <div class="card mb-3" id="domain-alignment">
                <div class="card-header">
                    <h5 class="mb-0">
                        <i class="bi {headerAnalysis.domain_alignment.aligned ? 'bi-check-circle-fill text-success' : headerAnalysis.domain_alignment.relaxed_aligned ? 'bi-check-circle text-info' : 'bi-x-circle-fill text-danger'}"></i>
                        Domain Alignment
                    </h5>
                </div>
                <div class="card-body">
                    <p class="card-text small text-muted">
                        Domain alignment ensures that the visible "From" domain matches the domain used for authentication (Return-Path or DKIM signature). Proper alignment is crucial for DMARC compliance, regardless of the policy. It helps prevent email spoofing by verifying that the sender domain is consistent across all authentication layers. Only one of the following lines needs to pass.
                    </p>
                </div>
                <div class="list-group list-group-flush">
                    <div class="list-group-item d-flex ps-0">
                        <div class="d-flex align-items-center justify-content-center" style="writing-mode: vertical-rl; transform: rotate(180deg); font-size: 1.5rem; font-weight: bold; min-width: 3rem;">
                            SPF
                        </div>
                        <div class="row flex-grow-1">
                            <div class="col-md-3">
                                <small class="text-muted">Strict Alignment</small>
                                <div>
                                    <span class="badge" class:bg-success={headerAnalysis.domain_alignment.aligned} class:bg-danger={!headerAnalysis.domain_alignment.aligned}>
                                        <i class="bi {headerAnalysis.domain_alignment.aligned ? 'bi-check-circle-fill' : 'bi-x-circle-fill'} me-1"></i>
                                        <strong>{headerAnalysis.domain_alignment.aligned ? 'Pass' : 'Fail'}</strong>
                                    </span>
                                </div>
                                <div class="small text-muted mt-1">Exact domain match</div>
                            </div>
                            <div class="col-md-3">
                                <small class="text-muted">Relaxed Alignment</small>
                                <div>
                                    <span class="badge" class:bg-success={headerAnalysis.domain_alignment.relaxed_aligned} class:bg-danger={!headerAnalysis.domain_alignment.relaxed_aligned}>
                                        <i class="bi {headerAnalysis.domain_alignment.relaxed_aligned ? 'bi-check-circle-fill' : 'bi-x-circle-fill'} me-1"></i>
                                        <strong>{headerAnalysis.domain_alignment.relaxed_aligned ? 'Pass' : 'Fail'}</strong>
                                    </span>
                                </div>
                                <div class="small text-muted mt-1">Organizational domain match</div>
                            </div>
                            <div class="col-md-3">
                                <small class="text-muted">From Domain</small>
                                <div><code>{headerAnalysis.domain_alignment.from_domain || '-'}</code></div>
                                {#if headerAnalysis.domain_alignment.from_org_domain && headerAnalysis.domain_alignment.from_org_domain !== headerAnalysis.domain_alignment.from_domain}
                                    <div class="small text-muted mt-1">Org: <code>{headerAnalysis.domain_alignment.from_org_domain}</code></div>
                                {/if}
                            </div>
                            <div class="col-md-3">
                                <small class="text-muted">Return-Path Domain</small>
                                <div><code>{headerAnalysis.domain_alignment.return_path_domain || '-'}</code></div>
                                {#if headerAnalysis.domain_alignment.return_path_org_domain && headerAnalysis.domain_alignment.return_path_org_domain !== headerAnalysis.domain_alignment.return_path_domain}
                                    <div class="small text-muted mt-1">Org: <code>{headerAnalysis.domain_alignment.return_path_org_domain}</code></div>
                                {/if}
                            </div>
                        </div>
                        {#if headerAnalysis.domain_alignment.issues && headerAnalysis.domain_alignment.issues.length > 0}
                            <div class="mt-3">
                                {#each headerAnalysis.domain_alignment.issues as issue}
                                    <div class="alert alert-{headerAnalysis.domain_alignment.relaxed_aligned ? 'info' : 'warning'} py-2 small mb-2">
                                        <i class="bi bi-{headerAnalysis.domain_alignment.relaxed_aligned ? 'info-circle' : 'exclamation-triangle'} me-1"></i>
                                        {issue}
                                    </div>
                                {/each}
                            </div>
                        {/if}

                        <!-- Alignment Information based on DMARC policy -->
                        {#if dmarcRecord && headerAnalysis.domain_alignment.return_path_domain && headerAnalysis.domain_alignment.return_path_domain !== headerAnalysis.domain_alignment.from_domain}
                            <div class="alert mt-2 mb-0 small py-2 {dmarcRecord.spf_alignment === 'strict' ? 'alert-warning' : 'alert-info'}">
                                {#if dmarcRecord.spf_alignment === 'strict'}
                                    <i class="bi bi-exclamation-triangle me-1"></i>
                                    <strong>Strict SPF alignment required</strong> — Your DMARC policy requires exact domain match. The Return-Path domain must exactly match the From domain for SPF to pass DMARC alignment.
                                {:else}
                                    <i class="bi bi-info-circle me-1"></i>
                                    <strong>Relaxed SPF alignment allowed</strong> — Your DMARC policy allows organizational domain matching. As long as both domains share the same organizational domain (e.g., mail.example.com and example.com), SPF alignment can pass.
                                {/if}
                            </div>
                        {/if}
                    </div>

                    {#each headerAnalysis.domain_alignment.dkim_domains as dkim_domain}
                        {@const dkim_aligned = dkim_domain.domain === headerAnalysis.domain_alignment.from_domain}
                        {@const dkim_relaxed_aligned = dkim_domain.org_domain === headerAnalysis.domain_alignment.from_org_domain}
                        <div class="list-group-item d-flex ps-0">
                            <div class="d-flex align-items-center justify-content-center" style="writing-mode: vertical-rl; transform: rotate(180deg); font-size: 1.5rem; font-weight: bold; min-width: 3rem;">
                                DKIM
                            </div>
                            <div class="flex-fill">
                                <div class="row flex-grow-1">
                                    <div class="col-md-3">
                                        <small class="text-muted">Strict Alignment</small>
                                        <div>
                                            <span class="badge" class:bg-success={dkim_aligned} class:bg-danger={!dkim_aligned}>
                                                <i class="bi {dkim_aligned ? 'bi-check-circle-fill' : 'bi-x-circle-fill'} me-1"></i>
                                                <strong>{dkim_aligned ? 'Pass' : 'Fail'}</strong>
                                            </span>
                                        </div>
                                        <div class="small text-muted mt-1">Exact domain match</div>
                                    </div>
                                    <div class="col-md-3">
                                        <small class="text-muted">Relaxed Alignment</small>
                                        <div>
                                            <span class="badge" class:bg-success={dkim_relaxed_aligned} class:bg-danger={!dkim_relaxed_aligned}>
                                                <i class="bi {dkim_relaxed_aligned ? 'bi-check-circle-fill' : 'bi-x-circle-fill'} me-1"></i>
                                                <strong>{dkim_relaxed_aligned ? 'Pass' : 'Fail'}</strong>
                                            </span>
                                        </div>
                                        <div class="small text-muted mt-1">Organizational domain match</div>
                                    </div>
                                    <div class="col-md-3">
                                        <small class="text-muted">From Domain</small>
                                        <div><code>{headerAnalysis.domain_alignment.from_domain || '-'}</code></div>
                                        {#if headerAnalysis.domain_alignment.from_org_domain && headerAnalysis.domain_alignment.from_org_domain !== headerAnalysis.domain_alignment.from_domain}
                                            <div class="small text-muted mt-1">Org: <code>{headerAnalysis.domain_alignment.from_org_domain}</code></div>
                                        {/if}
                                    </div>
                                    <div class="col-md-3">
                                        <small class="text-muted">Signature Domain</small>
                                        <div><code>{dkim_domain.domain || '-'}</code></div>
                                        {#if dkim_domain.domain !== dkim_domain.org_domain}
                                            <div class="small text-muted mt-1">Org: <code>{dkim_domain.org_domain}</code></div>
                                        {/if}
                                    </div>
                                </div>
                                {#if headerAnalysis.domain_alignment.issues && headerAnalysis.domain_alignment.issues.length > 0}
                                    <div class="mt-3">
                                        {#each headerAnalysis.domain_alignment.issues as issue}
                                            <div class="alert alert-{headerAnalysis.domain_alignment.relaxed_aligned ? 'info' : 'warning'} py-2 small mb-2">
                                                <i class="bi bi-{headerAnalysis.domain_alignment.relaxed_aligned ? 'info-circle' : 'exclamation-triangle'} me-1"></i>
                                                {issue}
                                            </div>
                                        {/each}
                                    </div>
                                {/if}

                                <!-- Alignment Information based on DMARC policy -->
                                {#if dmarcRecord && dkim_domain.domain !== headerAnalysis.domain_alignment.from_domain}
                                    {#if dkim_domain.org_domain === headerAnalysis.domain_alignment.from_org_domain}
                                        <div class="alert mt-2 mb-0 small py-2 {dmarcRecord.dkim_alignment === 'strict' ? 'alert-warning' : 'alert-info'}">
                                            {#if dmarcRecord.dkim_alignment === 'strict'}
                                                <i class="bi bi-exclamation-triangle me-1"></i>
                                                <strong>Strict DKIM alignment required</strong> — Your DMARC policy requires exact domain match. The DKIM signature domain must exactly match the From domain for DKIM to pass DMARC alignment.
                                            {:else}
                                                <i class="bi bi-info-circle me-1"></i>
                                                <strong>Relaxed DKIM alignment allowed</strong> — Your DMARC policy allows organizational domain matching. As long as both domains share the same organizational domain (e.g., mail.example.com and example.com), DKIM alignment can pass.
                                            {/if}
                                        </div>
                                    {/if}
                                {/if}
                            </div>
                        </div>
                    {/each}
                </div>
            </div>
        {/if}

        {#if headerAnalysis.headers && Object.keys(headerAnalysis.headers).length > 0}
            <div class="mt-3">
                <h5 style="margin-bottom: -1.3em">Headers</h5>
                <div class="table-responsive">
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th></th>
                                <th>When?</th>
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
                                    </td>
                                    <td>
                                        {#if check.importance}
                                            <small class="text-{check.importance === 'required' ? 'danger' : check.importance === 'recommended' ? 'warning' : 'secondary'}">
                                                {check.importance}
                                            </small>
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
                                        <small class="text-muted text-truncate" title={check.value}>{check.value || '-'}</small>
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
    </div>
</div>
