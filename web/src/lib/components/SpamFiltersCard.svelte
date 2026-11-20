<script lang="ts">
    import type { RspamdResult, UpstreamSpamVerdict, SpamAssassinResult } from "#lib/api/types.gen.js";
    import type { SectionStatus } from "#lib/sections.js";
    import ReportSection from "./ReportSection.svelte";
    import RspamdCard from "./RspamdCard.svelte";
    import UpstreamSpamVerdictCard from "./UpstreamSpamVerdictCard.svelte";
    import { upstreamSpamVerdictCards } from "./upstreamSpamVerdicts/index.js";
    import SpamAssassinCard from "./SpamAssassinCard.svelte";

    interface Props {
        spamassassin?: SpamAssassinResult;
        rspamd?: RspamdResult;
        /** The verdicts stamped upstream, before this instance saw the message. */
        upstreamSpamVerdicts?: UpstreamSpamVerdict[];
        spamGrade?: string;
        spamScore?: number;
        /** rspamd symbol to the anchor of the content check showing its advice. */
        adviceAnchors?: Record<string, string>;
        status?: SectionStatus;
        open?: boolean;
    }

    let {
        spamassassin,
        rspamd,
        upstreamSpamVerdicts = [],
        spamGrade,
        spamScore,
        adviceAnchors,
        status,
        open = true,
    }: Props = $props();
</script>

<ReportSection
    id="spam-details"
    title="Spam Filters"
    icon="bug"
    grade={spamGrade}
    score={spamScore}
    {status}
    {open}
>
    <!-- One item per filter: the rules between them run across the whole card, as the
         section's own, rather than stopping at the margins like those inside a filter. -->
    <div class="list-group list-group-flush">
        {#if spamassassin}
            <SpamAssassinCard {spamassassin} />
        {/if}
        {#if rspamd}
            <RspamdCard {rspamd} {adviceAnchors} />
        {/if}
        {#each upstreamSpamVerdicts as verdict (verdict.filter)}
            <!-- The filter's own card when the interface has one, a generic one otherwise. -->
            {@const Card = upstreamSpamVerdictCards[verdict.filter] ?? UpstreamSpamVerdictCard}
            <Card {verdict} />
        {/each}
        {#if !spamassassin && !rspamd && upstreamSpamVerdicts.length === 0}
            <p class="list-group-item py-3 text-muted mb-0">
                No spam filter produced a result for this message.
            </p>
        {/if}
    </div>
</ReportSection>
