<script lang="ts">
    import type { DnsResults, DomainAlignment, Issue } from "#lib/api/types.gen.js";
    import type { SectionStatus } from "#lib/sections.js";
    import BimiRecordDisplay from "./BimiRecordDisplay.svelte";
    import DkimRecordsDisplay from "./DkimRecordsDisplay.svelte";
    import DmarcRecordDisplay from "./DmarcRecordDisplay.svelte";
    import DomainInfoDisplay from "./DomainInfoDisplay.svelte";
    import HeloPtrMatchDisplay from "./HeloPtrMatchDisplay.svelte";
    import HeloSpfRecordDisplay from "./HeloSpfRecordDisplay.svelte";
    import MxRecordsDisplay from "./MxRecordsDisplay.svelte";
    import PtrForwardRecordsDisplay from "./PtrForwardRecordsDisplay.svelte";
    import PtrRecordsDisplay from "./PtrRecordsDisplay.svelte";
    import ReportSection from "./ReportSection.svelte";
    import ReturnOkDisplay from "./ReturnOkDisplay.svelte";
    import SenderOriginDisplay from "./SenderOriginDisplay.svelte";
    import SpfRecordsDisplay from "./SpfRecordsDisplay.svelte";

    interface Props {
        domainAlignment?: DomainAlignment;
        /**
         * What the alignment of the authenticating domains costs, as the header analysis
         * reports it: whether the Return-Path is one DMARC can count.
         */
        alignmentIssues?: Issue[];
        dnsResults?: DnsResults;
        dnsGrade?: string;
        dnsScore?: number;
        domainOnly?: boolean; // If true, only shows domain-level DNS records (no PTR, no DKIM, simplified view)
        status?: SectionStatus;
        open?: boolean;
    }

    let {
        domainAlignment,
        alignmentIssues,
        dnsResults,
        dnsGrade,
        dnsScore,
        domainOnly = false,
        status,
        open = true,
    }: Props = $props();

    // Both come from the hop the backend marked as inbound.
    const senderIp = $derived(dnsResults?.sender_ip);
    const heloHostname = $derived(dnsResults?.helo_hostname);

    const sameDomain = $derived(
        !dnsResults?.rp_domain || dnsResults.rp_domain === dnsResults.from_domain,
    );

    // A Return-Path of its own that DMARC does not count, alone or along with everything else.
    const rpMisaligned = $derived(
        !sameDomain &&
            (alignmentIssues ?? []).some(
                (i) => i.type === "return_path_misaligned" || i.type === "domain_misaligned",
            ),
    );
</script>

<ReportSection
    id="dns-details"
    title="DNS Records"
    icon="diagram-3"
    grade={dnsGrade}
    score={dnsScore}
    {status}
    {open}
>
    <div class="card-body">
        {#if !dnsResults}
            <p class="text-muted mb-0">No DNS results available</p>
        {:else}
            {#if dnsResults.errors && dnsResults.errors.length > 0}
                <div class="alert alert-warning mb-3">
                    <strong>Errors:</strong>
                    <ul class="mb-0">
                        {#each dnsResults.errors as error, i (i)}
                            <li>{error}</li>
                        {/each}
                    </ul>
                </div>
            {/if}

            {#if !domainOnly}
                <!-- Reverse IP Section -->
                {#if senderIp}
                    <div class="mb-3 pb-2 border-bottom">
                        <h5 class="mb-0 text-truncate">
                            Sending server: <code
                                >{heloHostname} ({dnsResults.ptr_records?.[0] || "Unknown"} [{senderIp}])</code
                            >
                        </h5>
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

                <!-- Where the sending address comes from -->
                <SenderOriginDisplay senderOrigin={dnsResults.sender_origin} />

                <!-- HELO / PTR Consistency -->
                <HeloPtrMatchDisplay
                    {heloHostname}
                    ptrRecords={dnsResults.ptr_records}
                    heloPtrMatch={dnsResults.helo_ptr_match}
                />

                <!-- SPF policy published for the announced HELO hostname (optional) -->
                <HeloSpfRecordDisplay
                    heloSpfRecord={dnsResults.helo_spf_record}
                    senderDomain={dnsResults.rp_domain ?? dnsResults.from_domain}
                    senderOrgDomain={domainAlignment?.return_path_org_domain ??
                        domainAlignment?.from_org_domain}
                />

                <!-- Return Address Reachability (ReturnOK) -->
                <ReturnOkDisplay returnOk={dnsResults.return_ok} />

                <!-- Return-Path Domain Section -->
                <div class="mb-3 pb-2 border-bottom mt-4">
                    <div class="d-flex align-items-center gap-2 flex-wrap">
                        <h5 class="mb-0 text-truncate">
                            Return-Path domain:
                            <code>{dnsResults.rp_domain || dnsResults.from_domain}</code>
                        </h5>
                        {#if rpMisaligned}
                            <span class="badge bg-danger ms-2">
                                <i class="bi bi-exclamation-triangle-fill"></i> Differs from From domain
                            </span>
                            <small>
                                <i class="bi bi-chevron-right"></i>
                                <a href="#domain-alignment">See domain alignment</a>
                            </small>
                        {:else}
                            <span class="badge bg-success ms-2">Same as From domain</span>
                        {/if}
                    </div>
                </div>

                <!-- What the Return-Path domain is, when another organization's -->
                <DomainInfoDisplay domainInfo={dnsResults.rp_domain_info} role="return-path" />

                <!-- MX Records for Return-Path Domain -->
                {#if dnsResults.rp_mx_records && dnsResults.rp_mx_records.length > 0}
                    <MxRecordsDisplay
                        id="dns-mx-return-path"
                        class="mb-3"
                        mxRecords={dnsResults.rp_mx_records}
                        title="Mail Exchange Records for Return-Path Domain"
                        description="These MX records handle bounce messages and non-delivery reports."
                    />
                {/if}
            {/if}

            <!-- SPF Records (for Return-Path Domain) -->
            <SpfRecordsDisplay
                spfRecords={dnsResults.spf_records}
                issues={dnsResults.issues?.spf}
            />

            {#if !domainOnly}
                <!-- From Domain Section -->
                <div class="mb-3 pb-2 border-bottom mt-4 d-flex align-items-center gap-2">
                    <h5 class="mb-0 text-truncate">
                        From domain: <code>{dnsResults.from_domain}</code>
                    </h5>
                    {#if dnsResults.rp_domain && dnsResults.rp_domain !== dnsResults.from_domain}
                        <span class="badge bg-danger ms-2">
                            <i class="bi bi-exclamation-triangle-fill"></i> Differs from Return-Path domain
                        </span>
                    {/if}
                </div>
            {/if}

            <!-- What the From domain is -->
            <DomainInfoDisplay domainInfo={dnsResults.from_domain_info} role="from" />

            <!-- MX Records for From Domain -->
            {#if dnsResults.from_mx_records && dnsResults.from_mx_records.length > 0}
                <MxRecordsDisplay
                    id="dns-mx-from"
                    class="mb-3"
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
            <DmarcRecordDisplay
                dmarcRecord={dnsResults.dmarc_record}
                fromDomain={dnsResults.from_domain}
            />

            <!-- BIMI Record -->
            <BimiRecordDisplay
                bimiRecord={dnsResults.bimi_record}
                dmarcRecord={dnsResults.dmarc_record}
            />
        {/if}
    </div>
</ReportSection>
