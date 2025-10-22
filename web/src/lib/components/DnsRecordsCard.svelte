<script lang="ts">
    import type { DNSResults } from "$lib/api/types.gen";
    import { getScoreColorClass } from "$lib/score";
    import GradeDisplay from "./GradeDisplay.svelte";
    import MxRecordsDisplay from "./MxRecordsDisplay.svelte";

    interface Props {
        dnsResults?: DNSResults;
        dnsGrade?: string;
        dnsScore?: number;
    }

    let { dnsResults, dnsGrade, dnsScore }: Props = $props();
</script>

<div class="card shadow-sm">
    <div class="card-header bg-white">
        <h4 class="mb-0 d-flex justify-content-between align-items-center">
            <span>
                <i class="bi bi-diagram-3 me-2"></i>
                DNS Records
            </span>
            <span>
                {#if dnsScore !== undefined}
                    <span class="badge bg-{getScoreColorClass(dnsScore)}">
                        {dnsScore}%
                    </span>
                {/if}
                {#if dnsGrade !== undefined}
                    <GradeDisplay grade={dnsGrade} size="small" />
                {/if}
            </span>
        </h4>
    </div>
    <div class="card-body">
        {#if !dnsResults}
            <p class="text-muted mb-0">No DNS results available</p>
        {:else}
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

            <!-- Return-Path Domain Section -->
            <div class="mb-3">
                <strong>Return-Path Domain:</strong> <code>{dnsResults.rp_domain || dnsResults.from_domain}</code>
                {#if dnsResults.rp_domain && dnsResults.rp_domain !== dnsResults.from_domain}
                    <span class="badge bg-danger ms-2"><i class="bi bi-exclamation-triangle-fill"></i> Different from From domain</span>
                    <small>
                        <i class="bi bi-chevron-right"></i>
                        <a href="#domain-alignment">See domain alignment</a>
                    </small>
                {:else}
                    <span class="badge bg-success ms-2">Same as From domain</span>
                {/if}
            </div>

            <!-- MX Records for Return-Path Domain -->
            {#if dnsResults.rp_mx_records && dnsResults.rp_mx_records.length > 0}
                <MxRecordsDisplay
                    mxRecords={dnsResults.rp_mx_records}
                    title="Mail Exchange Records for Return-Path Domain"
                    description="These MX records handle bounce messages and non-delivery reports."
                />
            {/if}

            <!-- SPF Records (for Return-Path Domain) -->
            {#if dnsResults.spf_records && dnsResults.spf_records.length > 0}
                <div class="mb-4">
                    <h5 class="text-muted mb-2">
                        <span class="badge bg-secondary">SPF</span> Sender Policy Framework
                    </h5>
                    <p class="small text-muted mb-2">SPF validates the Return-Path (envelope sender) domain.</p>
                    {#each dnsResults.spf_records as spf, index}
                        <div class="card mb-2">
                            <div class="card-body">
                                {#if spf.domain}
                                    <div class="mb-2">
                                        <strong>Domain:</strong> <code>{spf.domain}</code>
                                        {#if index > 0}
                                            <span class="badge bg-info ms-2">Included</span>
                                        {/if}
                                    </div>
                                {/if}
                                <div class="mb-2">
                                    <strong>Status:</strong>
                                    {#if spf.valid}
                                        <span class="badge bg-success">Valid</span>
                                    {:else}
                                        <span class="badge bg-danger">Invalid</span>
                                    {/if}
                                </div>
                                {#if spf.record}
                                    <div class="mb-2">
                                        <strong>Record:</strong><br>
                                        <code class="d-block mt-1 text-break">{spf.record}</code>
                                    </div>
                                {/if}
                                {#if spf.error}
                                    <div class="alert alert-{spf.valid ? 'warning' : 'danger'} mb-0 mt-2">
                                        <i class="bi bi-{spf.valid ? 'exclamation-triangle' : 'x-circle'} me-1"></i>
                                        <strong>{spf.valid ? 'Warning:' : 'Error:'}</strong> {spf.error}
                                    </div>
                                {/if}
                            </div>
                        </div>
                    {/each}
                </div>
            {/if}

            <hr>

            <!-- From Domain Section -->
            <div class="mb-3">
                <strong>From Domain:</strong> <code>{dnsResults.from_domain}</code>
                {#if dnsResults.rp_domain && dnsResults.rp_domain !== dnsResults.from_domain}
                    <span class="badge bg-danger ms-2"><i class="bi bi-exclamation-triangle-fill"></i> Different from Return-Path domain</span>
                {/if}
            </div>

            <!-- MX Records for From Domain -->
            {#if dnsResults.from_mx_records && dnsResults.from_mx_records.length > 0}
                <MxRecordsDisplay
                    mxRecords={dnsResults.from_mx_records}
                    title="Mail Exchange Records for From Domain"
                    description="These MX records handle replies to emails sent from this domain."
                />
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
