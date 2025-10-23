<script lang="ts">
    import type { DNSResults } from "$lib/api/types.gen";
    import { getScoreColorClass } from "$lib/score";
    import GradeDisplay from "./GradeDisplay.svelte";
    import MxRecordsDisplay from "./MxRecordsDisplay.svelte";
    import SpfRecordsDisplay from "./SpfRecordsDisplay.svelte";
    import DkimRecordsDisplay from "./DkimRecordsDisplay.svelte";
    import DmarcRecordDisplay from "./DmarcRecordDisplay.svelte";
    import BimiRecordDisplay from "./BimiRecordDisplay.svelte";

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
            <SpfRecordsDisplay spfRecords={dnsResults.spf_records} />

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
            <DkimRecordsDisplay dkimRecords={dnsResults.dkim_records} />

            <!-- DMARC Record -->
            <DmarcRecordDisplay dmarcRecord={dnsResults.dmarc_record} />

            <!-- BIMI Record -->
            <BimiRecordDisplay bimiRecord={dnsResults.bimi_record} />
        {/if}
    </div>
</div>
