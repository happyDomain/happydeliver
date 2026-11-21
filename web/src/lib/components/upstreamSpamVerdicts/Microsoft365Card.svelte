<script module lang="ts">
    /** The filter this card shows, as the backend names it. */
    export const filter = "microsoft365";
</script>

<script lang="ts">
    import {
        m365BclMeaning,
        m365Categories,
        m365FilterVerdicts,
        m365Site,
        m365UnderPresets,
        type Microsoft365Details,
    } from "#lib/microsoft365.js";
    import CheckCard from "../CheckCard.svelte";
    import FactRow from "../FactRow.svelte";
    import SpamEngine from "../SpamEngine.svelte";
    import VerdictFacts from "../VerdictFacts.svelte";
    import type { UpstreamSpamVerdictCardProps } from "./index.js";

    let { verdict }: UpstreamSpamVerdictCardProps = $props();

    const microsoft365 = $derived((verdict.details ?? {}) as Microsoft365Details);

    const counted = $derived(verdict.deliverability_grade !== undefined);

    const direction = $derived(
        microsoft365.direction === "outbound"
            ? "leaving the sender's tenant"
            : microsoft365.direction === "inbound"
              ? "entering a tenant"
              : microsoft365.direction === "internal"
                ? "within a tenant"
                : undefined,
    );

    const underPresets = $derived(m365UnderPresets(microsoft365));

    /** A code followed by what it stands for, when known. */
    function described(code: string, meanings: Record<string, string>): string {
        const meaning = meanings[code];
        return meaning ? `${code}, ${meaning}` : code;
    }
</script>

<SpamEngine
    id="microsoft365-details"
    name="Microsoft 365"
    subject={direction}
    verdict={verdict.verdict}
    isSpam={verdict.is_spam}
    deliverabilityScore={verdict.deliverability_score}
    deliverabilityGrade={verdict.deliverability_grade}
>
    <CheckCard
        title="Microsoft's verdict"
        status={verdict.is_spam ? "fail" : counted ? "warn" : "pass"}
        summary={verdict.verdict}
        open={counted}
        docs={[m365Site]}
    >
        <div class="card-body">
            <VerdictFacts title="Reported by Microsoft 365" raw={microsoft365.report}>
                {#if direction}
                    <FactRow label="Filtered while" value={direction} />
                {/if}
                {#if microsoft365.bcl !== undefined}
                    <FactRow
                        label="Bulk complaints (BCL)"
                        value="{microsoft365.bcl}, {m365BclMeaning(microsoft365.bcl)}"
                        ok={microsoft365.bcl < 5}
                        okLabel={microsoft365.bcl < 5 ? "below the bulk thresholds" : "bulk"}
                    />
                {/if}
                {#if microsoft365.filter_verdict}
                    <FactRow
                        label="Filtering verdict (SFV)"
                        value={described(microsoft365.filter_verdict, m365FilterVerdicts)}
                        mono
                    />
                {/if}
                {#if microsoft365.category}
                    <FactRow
                        label="Threat policy (CAT)"
                        value={described(microsoft365.category, m365Categories)}
                        mono
                    />
                {/if}
                {#if microsoft365.bulk}
                    <FactRow label="Bulk (SRV)" value="identified as bulk by spam filtering" />
                {/if}
                {#if underPresets}
                    <FactRow label="Under stricter policies" value={underPresets} />
                {/if}
                {#if microsoft365.scl !== undefined}
                    <FactRow
                        label="Spam confidence (SCL)"
                        value="{microsoft365.scl}, informational: Microsoft no longer decides on it"
                    />
                {/if}
            </VerdictFacts>
            <p class="check-about">
                Microsoft 365 filtered this message and left its verdict in the headers, before it
                reached this instance. A verdict against the message lowers the spam grade; a
                favourable one leaves the grade to the other filters.
            </p>
        </div>
    </CheckCard>
</SpamEngine>
