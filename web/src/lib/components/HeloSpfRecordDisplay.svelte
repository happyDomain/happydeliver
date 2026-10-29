<script lang="ts">
    import type { Issue, SpfRecord } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";
    import SpfRecordTree from "./SpfRecordTree.svelte";

    interface Props {
        heloSpfRecords?: SpfRecord[];
        issues?: Issue[];
    }

    let { heloSpfRecords, issues }: Props = $props();

    const root = $derived(heloSpfRecords?.[0]);

    // A published policy is a bonus, never a requirement: its absence is a suggestion,
    // so the card itself is never styled as an error.
    const hasPolicy = $derived(!!root?.valid);
</script>

{#if heloSpfRecords && root}
    <CheckCard
        id="dns-helo-spf"
        title="SPF for the HELO Hostname"
        tag="SPF"
        status={hasPolicy ? "pass" : "info"}
        summary={root.record ?? "No policy published (optional)"}
        summaryFoldedOnly={!!root.record}
        docs={[docs.spfHelo, docs.spfLookupLimit]}
        {issues}
    >
        <div class="card-body">
            <SpfRecordTree records={heloSpfRecords} optional />
            <p class="check-about">
                SPF can authenticate, besides the envelope sender, the hostname the server announces
                at HELO (<a
                    href="https://www.rfc-editor.org/rfc/rfc7208.html#section-2.3"
                    target="_blank"
                    rel="noreferrer">RFC 7208, section 2.3</a
                >). A bounce has an empty envelope sender, so it is the only identity SPF can check
                there (<a
                    href="https://www.rfc-editor.org/rfc/rfc7208.html#section-2.4"
                    target="_blank"
                    rel="noreferrer">section 2.4</a
                >). Optional: this check never affects the score.
            </p>
        </div>
    </CheckCard>
{/if}
