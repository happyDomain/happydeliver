<script lang="ts">
    import type { DnsResults, Issue } from "#lib/api/types.gen.js";
    import type { SectionStatus } from "#lib/sections.js";
    import BimiRecordDisplay from "./BimiRecordDisplay.svelte";
    import CheckList from "./CheckList.svelte";
    import DkimRecordsDisplay from "./DkimRecordsDisplay.svelte";
    import DmarcRecordDisplay from "./DmarcRecordDisplay.svelte";
    import DomainInfoDisplay from "./DomainInfoDisplay.svelte";
    import HeloPtrMatchDisplay from "./HeloPtrMatchDisplay.svelte";
    import HeloSpfRecordDisplay from "./HeloSpfRecordDisplay.svelte";
    import IssueNote from "./IssueNote.svelte";
    import MxRecordsDisplay from "./MxRecordsDisplay.svelte";
    import PtrForwardRecordsDisplay from "./PtrForwardRecordsDisplay.svelte";
    import PtrRecordsDisplay from "./PtrRecordsDisplay.svelte";
    import ReportSection from "./ReportSection.svelte";
    import SenderOriginDisplay from "./SenderOriginDisplay.svelte";
    import SpfRecordsDisplay from "./SpfRecordsDisplay.svelte";

    interface Props {
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

    // What the analyser found to change, by the check showing it
    const issues = $derived(dnsResults?.issues ?? {});

    // One domain serving as both identities is shown once, its checks under one heading.
    const rpDomain = $derived(dnsResults?.rp_domain || dnsResults?.from_domain);
    const sameDomain = $derived(domainOnly || rpDomain === dnsResults?.from_domain);

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
            <!-- What the checks below could not see -->
            {#each issues.lookups ?? [] as issue, i (i)}
                <IssueNote {issue} />
            {:else}
                <!-- An analysis that stopped early reports its failures without issues -->
                {#each dnsResults.errors ?? [] as error, i (i)}
                    <p class="text-danger">{error}</p>
                {/each}
            {/each}

            {#if !domainOnly && (senderIp || heloHostname)}
                <CheckList title="Sending server" subject={heloHostname ?? senderIp}>
                    {#snippet aside()}
                        {#if heloHostname && senderIp}
                            <code class="text-body-secondary">{senderIp}</code>
                        {/if}
                    {/snippet}
                    <SenderOriginDisplay senderOrigin={dnsResults.sender_origin} />
                    <PtrRecordsDisplay
                        ptrRecords={dnsResults.ptr_records}
                        {senderIp}
                        issues={issues.ptr}
                    />
                    <PtrForwardRecordsDisplay
                        ptrRecords={dnsResults.ptr_records}
                        ptrForwardRecords={dnsResults.ptr_forward_records}
                        {senderIp}
                        issues={issues.fcrdns}
                    />
                    <HeloPtrMatchDisplay
                        {heloHostname}
                        ptrRecords={dnsResults.ptr_records}
                        heloPtrMatch={dnsResults.helo_ptr_match}
                        issues={issues.helo_ptr}
                    />
                    <HeloSpfRecordDisplay
                        heloSpfRecord={dnsResults.helo_spf_record}
                        issues={issues.helo_spf}
                    />
                </CheckList>
            {/if}

            {#if !sameDomain}
                <CheckList title="Return-Path domain" subject={rpDomain}>
                    {#snippet aside()}
                        {#if rpMisaligned}
                            <a class="small text-danger" href="#domain-alignment"
                                >not aligned with the From domain</a
                            >
                        {/if}
                    {/snippet}
                    <DomainInfoDisplay
                        domainInfo={dnsResults.rp_domain_info}
                        role="return-path"
                        issues={issues.registration_return_path}
                    />
                    <MxRecordsDisplay
                        id="dns-mx-return-path"
                        mxRecords={dnsResults.rp_mx_records}
                        returnOk={dnsResults.return_ok?.return_path}
                        description="These servers receive the bounces of your messages."
                        issues={issues.mx_return_path}
                    />
                    <SpfRecordsDisplay spfRecords={dnsResults.spf_records} issues={issues.spf} />
                </CheckList>
            {/if}

            <!-- Without a From domain, nothing below was looked up -->
            {#if dnsResults.from_domain}
                <CheckList
                    title={sameDomain && !domainOnly ? "Sender domain" : "From domain"}
                    subject={dnsResults.from_domain}
                >
                    {#snippet aside()}
                        {#if sameDomain && !domainOnly}
                            <span class="text-body-secondary">From and Return-Path</span>
                        {/if}
                    {/snippet}
                    <DomainInfoDisplay
                        domainInfo={dnsResults.from_domain_info}
                        role="from"
                        issues={issues.registration_from}
                    />
                    <MxRecordsDisplay
                        id="dns-mx-from"
                        mxRecords={dnsResults.from_mx_records}
                        returnOk={dnsResults.return_ok?.from ?? dnsResults.return_ok?.return_path}
                        description={sameDomain && !domainOnly
                            ? "These servers receive the replies and the bounces of your messages."
                            : "These servers receive the replies to your messages."}
                        issues={sameDomain
                            ? [...(issues.mx_from ?? []), ...(issues.mx_return_path ?? [])]
                            : issues.mx_from}
                    />
                    {#if sameDomain}
                        <SpfRecordsDisplay
                            spfRecords={dnsResults.spf_records}
                            issues={issues.spf}
                        />
                    {/if}
                    {#if !domainOnly}
                        <DkimRecordsDisplay
                            dkimRecords={dnsResults.dkim_records}
                            issues={issues.dkim}
                        />
                    {/if}
                    <DmarcRecordDisplay
                        dmarcRecord={dnsResults.dmarc_record}
                        fromDomain={dnsResults.from_domain}
                        issues={issues.dmarc}
                    />
                    <BimiRecordDisplay bimiRecord={dnsResults.bimi_record} issues={issues.bimi} />
                </CheckList>
            {/if}
        {/if}
    </div>
</ReportSection>
