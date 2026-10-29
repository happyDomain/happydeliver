<script lang="ts">
    import type { Snippet } from "svelte";

    import type { DocLink } from "#lib/docs.js";
    import { getScoreColorClass } from "#lib/score.js";
    import CheckList from "./CheckList.svelte";
    import GradeDisplay from "./GradeDisplay.svelte";
    import SpamScoreGauge, { type GaugeStep } from "./SpamScoreGauge.svelte";

    interface Props {
        /** Where links to this filter's verdict lead. */
        id: string;
        name: string;
        /** What ran the filter: its version, its server. */
        subject?: string;
        score: number;
        /** In increasing order; the last one is where the message is treated as spam. */
        steps: GaugeStep[];
        /** What becomes of the message below the first step. */
        base: string;
        /** What the filter makes of the message, said on the score. */
        verdict: string;
        isSpam: boolean;
        deliverabilityScore?: number;
        deliverabilityGrade?: string;
        /** How the filter decides, for a reader who does not know. */
        about: string;
        /** The filter's own site, linked at the end of what it does. */
        site?: DocLink;
        /** The rules behind the verdict, as rows of checks. */
        children: Snippet;
    }

    let {
        id,
        name,
        subject,
        score,
        steps,
        base,
        verdict,
        isSpam,
        deliverabilityScore,
        deliverabilityGrade,
        about,
        site,
        children,
    }: Props = $props();

    const tone = $derived<"success" | "warning" | "danger">(
        isSpam ? "danger" : (deliverabilityScore ?? 100) < 100 ? "warning" : "success",
    );
    // SpamAssassin names itself in its version string ("SpamAssassin 4.0.2 (2025-08-27) on
    // example.net"): said once in the title is enough.
    const shownSubject = $derived(
        subject?.toLowerCase().startsWith(name.toLowerCase() + " ")
            ? subject.slice(name.length + 1)
            : subject,
    );
</script>

<!-- One filter: its verdict heads the rules that add up to it, rather than sitting among
     them as one more check. -->
<section class="spam-engine list-group-item p-0" {id}>
    <header
        class="engine-header d-flex flex-wrap align-items-center row-gap-2 column-gap-3 px-3 py-2 bg-body-tertiary"
    >
        <h5 class="mb-0 fs-5 d-flex flex-wrap align-items-baseline column-gap-2">
            <span class="fw-semibold">{name}</span>
            {#if shownSubject}
                <small class="fs-6 text-body-secondary fw-normal">{shownSubject}</small>
            {/if}
        </h5>
        <!-- As large as the section's own, which they are the parts of -->
        <span class="ms-auto d-inline-flex align-items-center gap-2">
            {#if deliverabilityScore !== undefined}
                <span class="badge fs-6 bg-{getScoreColorClass(deliverabilityScore)}">
                    {deliverabilityScore}%
                </span>
            {/if}
            {#if deliverabilityGrade !== undefined}
                <GradeDisplay grade={deliverabilityGrade} size="small" />
            {/if}
        </span>
    </header>

    <div class="engine-body px-3 pt-3 pb-2">
        <!-- The verdict, at a glance: the score and what it means, then where it falls. -->
        <div class="d-flex flex-wrap align-items-center row-gap-1 column-gap-4 mb-2">
            <div class="d-flex align-items-center gap-3 pb-2">
                <span class="score fw-bold lh-1 text-{tone}-emphasis">{score.toFixed(1)}</span>
                <span
                    class="badge rounded-pill border text-{tone}-emphasis bg-{tone}-subtle border-{tone}-subtle"
                >
                    <i
                        class="bi {tone === 'success'
                            ? 'bi-check-circle-fill'
                            : tone === 'warning'
                              ? 'bi-arrow-up-circle-fill'
                              : 'bi-x-circle-fill'} me-1"
                        aria-hidden="true"
                    ></i>{verdict}
                </span>
            </div>
            <div class="meter">
                <SpamScoreGauge
                    {score}
                    {steps}
                    {base}
                    {tone}
                    label="{name} score against its thresholds"
                />
            </div>
        </div>
        <p class="check-about mb-3">
            {about}
            {#if site}
                <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- external site -->
                <a class="text-nowrap" href={site.url} target="_blank" rel="noopener noreferrer"
                    >{site.label}<i class="bi bi-box-arrow-up-right ms-1" aria-hidden="true"></i></a
                >
            {/if}
        </p>

        <CheckList>
            {@render children()}
        </CheckList>
    </div>
</section>

<style>
    /* An item of the section's list group: the section is the only card, the rules between
       the filters running across it. */
    .spam-engine {
        scroll-margin-top: 1rem;
    }

    /* A band across the card naming the filter: tinted rather than framed, so it heads what
       follows without becoming a card of its own. */
    .engine-header {
        border-bottom: 1px solid var(--bs-border-color-translucent);
    }

    .engine-body {
        /* The list group's rule follows: one of its own under the last row would double it */
        :global(details.check-row:last-child) {
            border-bottom: 0;
        }
    }

    .score {
        font-size: 2rem;
        font-variant-numeric: tabular-nums;
    }

    /* All the width the score leaves: a longer bar reads more precisely. */
    .meter {
        flex: 1 1 12rem;
        min-width: 0;
    }
</style>
