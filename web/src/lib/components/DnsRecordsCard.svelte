<script lang="ts">
    import type { DomainAlignment, DnsResults, ReceivedHop } from "$lib/api/types.gen";
    import { getScoreColorClass } from "$lib/score";
    import { theme } from "$lib/stores/theme";
    import GradeDisplay from "./GradeDisplay.svelte";
    import MxRecordsDisplay from "./MxRecordsDisplay.svelte";
    import SpfRecordsDisplay from "./SpfRecordsDisplay.svelte";
    import DkimRecordsDisplay from "./DkimRecordsDisplay.svelte";
    import DmarcRecordDisplay from "./DmarcRecordDisplay.svelte";
    import BimiRecordDisplay from "./BimiRecordDisplay.svelte";
    import PtrRecordsDisplay from "./PtrRecordsDisplay.svelte";
    import PtrForwardRecordsDisplay from "./PtrForwardRecordsDisplay.svelte";

    interface Props {
        domainAlignment?: DomainAlignment;
        dnsResults?: DnsResults;
        dnsGrade?: string;
        dnsScore?: number;
        receivedChain?: ReceivedHop[];
        domainOnly?: boolean; // If true, only shows domain-level DNS records (no PTR, no DKIM, simplified view)
    }

    let { domainAlignment, dnsResults, dnsGrade, dnsScore, receivedChain, domainOnly = false }: Props = $props();

    // Extract sender IP from first hop
    const senderIp = $derived(
        receivedChain && receivedChain.length > 0 ? receivedChain[0].ip : undefined,
    );
</script>

<div class="card shadow-sm" id="dns-details">
    <div class="card-header {$theme === 'light' ? 'bg-white' : 'bg-dark'}">
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

            {#if !domainOnly}
                <!-- Reverse IP Section -->
                {#if receivedChain && receivedChain.length > 0}
                    <div class="mb-3 d-flex align-items-center gap-2">
                        <h4 class="mb-0 text-truncate">
                            Received from: <code>{receivedChain[0].from} ({receivedChain[0].reverse || "Unknown"} [{receivedChain[0].ip}])</code>
                        </h4>
                    </div>
                {/if}

                <!-- PTR Records Section -->
                <PtrRecordsDisplay ptrRecords={dnsResults.ptr_records} {senderIp} />

                <!-- Forward-Confirmed Reverse DNS -->
                <PtrForwardRecordsDisplay
                    ptrRecords={dnsResults.ptr_records}
                    ptrForwardRecords={dnsResults.ptr_forward_records}
                    {senderIp}
                />

                <hr class="my-4" />

                <!-- Return-Path Domain Section -->
                <div class="mb-3">
                    <div class="d-flex align-items-center gap-2 flex-wrap">
                        <h4 class="mb-0 text-truncate">
                            Return-Path Domain: <code>{dnsResults.rp_domain || dnsResults.from_domain}</code>
                        </h4>
                        {#if (domainAlignment && !domainAlignment.aligned && !domainAlignment.relaxed_aligned) || (domainAlignment && !domainAlignment.aligned && domainAlignment.relaxed_aligned && dnsResults.dmarc_record && dnsResults.dmarc_record.spf_alignment === "strict") || (!domainAlignment && dnsResults.rp_domain && dnsResults.rp_domain !== dnsResults.from_domain)}
                            <span class="badge bg-danger ms-2"><i class="bi bi-exclamation-triangle-fill"></i> Differs from From domain</span>
                            <small>
                                <i class="bi bi-chevron-right"></i>
                                <a href="#domain-alignment">See domain alignment</a>
                            </small>
                        {:else}
                            <span class="badge bg-success ms-2">Same as From domain</span>
                        {/if}
                    </div>
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
            {/if}

            <!-- SPF Records (for Return-Path Domain) -->
            <SpfRecordsDisplay spfRecords={dnsResults.spf_records} dmarcRecord={dnsResults.dmarc_record} />

            {#if !domainOnly}
                <hr class="my-4">

                <!-- From Domain Section -->
                <div class="mb-3 d-flex align-items-center gap-2">
                    <h4 class="mb-0 text-truncate">
                        From Domain: <code>{dnsResults.from_domain}</code>
                    </h4>
                    {#if dnsResults.rp_domain && dnsResults.rp_domain !== dnsResults.from_domain}
                        <span class="badge bg-danger ms-2"><i class="bi bi-exclamation-triangle-fill"></i> Differs from Return-Path domain</span>
                    {/if}
                </div>
            {/if}

                <!-- MX Records for From Domain -->
                {#if dnsResults.from_mx_records && dnsResults.from_mx_records.length > 0}
                    <MxRecordsDisplay
                        class="mb-4"
                        mxRecords={dnsResults.from_mx_records}
                        title="Mail Exchange Records for From Domain"
                        description="These MX records handle replies to emails sent from this domain."
                    />
                {/if}

            {#if !domainOnly}
                <!-- DKIM Records -->
                <DkimRecordsDisplay dkimRecords={dnsResults.dkim_records} />
            {/if}

                <!-- DMARC Record -->
                <DmarcRecordDisplay dmarcRecord={dnsResults.dmarc_record} />

                <!-- BIMI Record -->
                <BimiRecordDisplay bimiRecord={dnsResults.bimi_record} />
        {/if}
    </div>
</div>
