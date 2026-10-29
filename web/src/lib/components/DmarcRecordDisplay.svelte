<script lang="ts">
    import type { DmarcRecord, Issue } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        dmarcRecord?: DmarcRecord;
        fromDomain?: string;
        /** What the analyser found to change about the record. */
        issues?: Issue[];
        /** Forces the card open or folded; by default it opens when something is wrong. */
        open?: boolean;
    }

    let { dmarcRecord, fromDomain, issues, open }: Props = $props();

    const isFallback = $derived(
        !!dmarcRecord?.domain && !!fromDomain && dmarcRecord.domain !== fromDomain,
    );
    // A single-label domain (no dot) is a TLD/PSD level fallback
    const isPsdFallback = $derived(isFallback && !dmarcRecord?.domain?.includes("."));

    const policyMeaning: Record<string, string> = {
        reject: "failing mail is rejected",
        quarantine: "failing mail goes to spam",
        none: "monitoring only, failing mail is delivered",
    };

    const alignmentMeaning: Record<string, string> = {
        relaxed: "subdomains of the From domain match",
        strict: "only the exact From domain matches",
    };
</script>

{#snippet policy(value: string | undefined)}
    <code>{value}</code>
    {#if value && policyMeaning[value]}
        <span class="text-body-secondary">, {policyMeaning[value]}</span>
    {/if}
{/snippet}

{#if dmarcRecord}
    <CheckCard
        id="dns-dmarc"
        title="Domain-based Message Authentication"
        tag="DMARC"
        status={dmarcRecord.valid ? "pass" : "fail"}
        summary={dmarcRecord.record ?? dmarcRecord.error ?? "No DMARC record"}
        summaryFoldedOnly={!!dmarcRecord.record}
        docs={[docs.dmarc, docs.dmarcPolicy, docs.dmarcbis, docs.dmarcV1]}
        {issues}
        {open}
    >
        <div class="card-body">
            <dl class="check-facts">
                {#if dmarcRecord.record}
                    <dt>Record</dt>
                    <dd><code>{dmarcRecord.record}</code></dd>
                {/if}
                {#if isFallback}
                    <dt>Found at</dt>
                    <dd>
                        <code>{dmarcRecord.domain}</code>
                        <div class="small text-body-secondary">
                            {fromDomain} has no record of its own: this one is inherited from {isPsdFallback
                                ? "the Public Suffix Domain"
                                : "the organizational domain"} through the DMARCbis DNS tree walk.
                        </div>
                    </dd>
                {/if}
                {#if dmarcRecord.policy}
                    <dt>Policy</dt>
                    <dd>{@render policy(dmarcRecord.policy)}</dd>
                    <dt>Subdomains</dt>
                    <dd>
                        {#if dmarcRecord.subdomain_policy}
                            {@render policy(dmarcRecord.subdomain_policy)}
                        {:else}
                            <span class="text-body-secondary">same as the domain</span>
                        {/if}
                    </dd>
                {/if}
                {#if dmarcRecord.nonexistent_subdomain_policy}
                    <dt>Non-existent subdomains</dt>
                    <dd>
                        {@render policy(dmarcRecord.nonexistent_subdomain_policy)}
                        <span class="small text-body-secondary">(np=, DMARCbis)</span>
                    </dd>
                {/if}
                {#if dmarcRecord.test_mode}
                    <dt>Test mode</dt>
                    <dd>
                        <code>t=y</code>
                        <span class="text-body-secondary"
                            >, receivers apply the policy one level softer</span
                        >
                    </dd>
                {/if}
                {#if dmarcRecord.percentage !== undefined}
                    <dt>Applies to</dt>
                    <dd>
                        {dmarcRecord.percentage}% of failing mail
                        <span class="small text-body-secondary">(pct=, removed in DMARCbis)</span>
                    </dd>
                {/if}
                {#if dmarcRecord.psd === "y" || dmarcRecord.psd === "n"}
                    <dt>Public suffix</dt>
                    <dd>
                        <code>psd={dmarcRecord.psd}</code>
                        <span class="text-body-secondary">
                            {dmarcRecord.psd === "y"
                                ? ", applies to subdomains without a record of their own"
                                : ", this is an organizational domain boundary"}
                        </span>
                    </dd>
                {/if}
                {#if dmarcRecord.spf_alignment}
                    <dt>SPF alignment</dt>
                    <dd>
                        {dmarcRecord.spf_alignment}
                        <span class="text-body-secondary"
                            >, {alignmentMeaning[dmarcRecord.spf_alignment] ?? ""}</span
                        >
                    </dd>
                {/if}
                {#if dmarcRecord.dkim_alignment}
                    <dt>DKIM alignment</dt>
                    <dd>
                        {dmarcRecord.dkim_alignment}
                        <span class="text-body-secondary"
                            >, {alignmentMeaning[dmarcRecord.dkim_alignment] ?? ""}</span
                        >
                    </dd>
                {/if}
                {#if dmarcRecord.error}
                    <dt>Error</dt>
                    <dd class="text-danger">{dmarcRecord.error}</dd>
                {/if}
            </dl>
            <p class="check-about">
                DMARC tells receivers what to do with mail whose From domain is not vouched for by
                an aligned SPF or DKIM result, and where to send reports about it.
            </p>
        </div>
    </CheckCard>
{/if}
