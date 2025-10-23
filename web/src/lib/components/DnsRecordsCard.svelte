<script lang="ts">
    import type { DNSResults } from "$lib/api/types.gen";
    import { getScoreColorClass } from "$lib/score";
    import GradeDisplay from "./GradeDisplay.svelte";
    import MxRecordsDisplay from "./MxRecordsDisplay.svelte";
    import DmarcRecordDisplay from "./DmarcRecordDisplay.svelte";

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
            <div class="mb-3 d-flex align-items-center gap-2">
                <h4 class="mb-0">
                    Return-Path Domain: <code>{dnsResults.rp_domain || dnsResults.from_domain}</code>
                </h4>
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
                    class="mb-4"
                    mxRecords={dnsResults.rp_mx_records}
                    title="Mail Exchange Records for Return-Path Domain"
                    description="These MX records handle bounce messages and non-delivery reports."
                />
            {/if}

            <!-- SPF Records (for Return-Path Domain) -->
            {#if dnsResults.spf_records && dnsResults.spf_records.length > 0}
                {@const spfIsValid = dnsResults.spf_records.reduce((acc, r) => acc && r.valid, true)}
                <div class="card mb-4">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="text-muted mb-2">
                            <i
                                class="bi"
                                class:bi-check-circle-fill={spfIsValid}
                                class:text-success={spfIsValid}
                                class:bi-x-circle-fill={!spfIsValid}
                                class:text-danger={!spfIsValid}
                            ></i>
                            Sender Policy Framework
                        </h5>
                        <span class="badge bg-secondary">SPF</span>
                    </div>
                    <div class="card-body pb-0">
                        <p class="card-text small text-muted mb-0">SPF specifies which mail servers are authorized to send emails on behalf of your domain. Receiving servers check the sender's IP address against your SPF record to prevent email spoofing.</p>
                    </div>
                    <div class="list-group list-group-flush">
                        {#each dnsResults.spf_records as spf, index}
                            <div class="list-group-item">
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
                        {/each}
                    </div>
                </div>
            {/if}

            <hr class="my-4">

            <!-- From Domain Section -->
            <div class="mb-3 d-flex align-items-center gap-2">
                <h4 class="mb-0">
                    From Domain: <code>{dnsResults.from_domain}</code>
                </h4>
                {#if dnsResults.rp_domain && dnsResults.rp_domain !== dnsResults.from_domain}
                    <span class="badge bg-danger ms-2"><i class="bi bi-exclamation-triangle-fill"></i> Different from Return-Path domain</span>
                {/if}
            </div>

            <!-- MX Records for From Domain -->
            {#if dnsResults.from_mx_records && dnsResults.from_mx_records.length > 0}
                <MxRecordsDisplay
                    class="mb-4"
                    mxRecords={dnsResults.from_mx_records}
                    title="Mail Exchange Records for From Domain"
                    description="These MX records handle replies to emails sent from this domain."
                />
            {/if}

            <!-- DKIM Records -->
            {#if dnsResults.dkim_records && dnsResults.dkim_records.length > 0}
                {@const dkimIsValid = dnsResults.dkim_records.reduce((acc, r) => acc && r.valid, true)}
                <div class="card mb-4">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="text-muted mb-0">
                            <i
                                class="bi"
                                class:bi-check-circle-fill={dkimIsValid}
                                class:text-success={dkimIsValid}
                                class:bi-x-circle-fill={!dkimIsValid}
                                class:text-danger={!dkimIsValid}
                            ></i>
                            DomainKeys Identified Mail
                        </h5>
                        <span class="badge bg-secondary">DKIM</span>
                    </div>
                    <div class="card-body pb-0">
                        <p class="card-text small text-muted mb-0">DKIM cryptographically signs your emails, proving they haven't been tampered with in transit. Receiving servers verify this signature against your DNS records.</p>
                    </div>
                    <div class="list-group list-group-flush">
                        {#each dnsResults.dkim_records as dkim}
                            <div class="list-group-item">
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
                                        <code class="d-block mt-1 text-break small text-truncate">{dkim.record}</code>
                                    </div>
                                {/if}
                                {#if dkim.error}
                                    <div class="text-danger">
                                        <strong>Error:</strong> {dkim.error}
                                    </div>
                                {/if}
                            </div>
                        {/each}
                    </div>
                </div>
            {/if}

            <!-- DMARC Record -->
            <DmarcRecordDisplay dmarcRecord={dnsResults.dmarc_record} />

            <!-- BIMI Record -->
            {#if dnsResults.bimi_record}
                <div class="card mb-4">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="text-muted mb-0">
                            <i
                                class="bi"
                                class:bi-check-circle-fill={dnsResults.bimi_record.valid}
                                class:text-success={dnsResults.bimi_record.valid}
                                class:bi-x-circle-fill={!dnsResults.bimi_record.valid}
                                class:text-danger={!dnsResults.bimi_record.valid}
                            ></i>
                            Brand Indicators for Message Identification
                        </h5>
                        <span class="badge bg-secondary">BIMI</span>
                    </div>
                    <div class="card">
                        <div class="card-body">
                            <p class="card-text small text-muted mb-2">BIMI allows your brand logo to be displayed next to your emails in supported mail clients. Requires strong DMARC enforcement (quarantine or reject policy) and optionally a Verified Mark Certificate (VMC).</p>
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
