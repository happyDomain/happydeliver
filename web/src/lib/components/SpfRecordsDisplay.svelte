<script lang="ts">
    import type { Issue, SpfRecord } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";
    import SpfRecordTree from "./SpfRecordTree.svelte";

    interface Props {
        spfRecords?: SpfRecord[];
        issues?: Issue[];
    }

    let { spfRecords, issues }: Props = $props();

    const spfIsValid = $derived(spfRecords?.every((r) => r.valid) ?? false);
</script>

{#if spfRecords && spfRecords.length > 0}
    <CheckCard
        id="dns-spf"
        title="Sender Policy Framework"
        tag="SPF"
        status={spfIsValid ? "pass" : "fail"}
        summary={spfRecords[0].record ?? spfRecords[0].error}
        summaryFoldedOnly={!!spfRecords[0].record}
        docs={[docs.spf, docs.spfAll, docs.spfLookupLimit]}
        {issues}
    >
        <div class="card-body">
            <SpfRecordTree records={spfRecords} />
            <p class="check-about">
                SPF lists the servers allowed to send mail for the envelope sender domain. Receivers
                check the sending IP against it, term by term, and the first one that matches
                decides; an include only matches when the included record lets the server pass.
            </p>
        </div>
    </CheckCard>
{/if}
