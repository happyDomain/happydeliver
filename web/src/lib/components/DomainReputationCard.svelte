<script lang="ts">
    import type { DomainBlacklistResult, DomainBlacklistSourceResult } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import type { SectionStatus } from "#lib/sections.js";
    import CheckCard, { type CheckStatus } from "./CheckCard.svelte";
    import CheckList from "./CheckList.svelte";
    import ReportSection from "./ReportSection.svelte";

    interface Props {
        blacklist: DomainBlacklistResult;
        // The domain the check was asked about, to tell whether the sources
        // were queried for another, registered, one.
        domain: string;
        /** Defaults to unfolded only when the domain is listed. */
        open?: boolean;
        class?: string;
    }

    let { blacklist, domain, open, class: className = "mt-4" }: Props = $props();

    const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

    // The backend decides the verdict; the counts shown here are derived
    // from the same results array it renders below, so they cannot diverge.
    const count = $derived({
        answered: blacklist.results.filter((r) => r.status === "clean" || r.status === "listed")
            .length,
        errored: blacklist.results.filter((r) => r.status === "errored").length,
        pending: blacklist.results.filter((r) => r.status === "pending").length,
        listed: blacklist.results.filter((r) => r.status === "listed").length,
        critical: blacklist.results.filter((r) => r.status === "listed" && r.severity === "crit")
            .length,
        // The backend only sends the sources enabled on this instance.
        enabled: blacklist.results.length,
    });

    const listed = $derived(
        blacklist.verdict === "listed" || blacklist.verdict === "listed_critical",
    );

    const status: SectionStatus = $derived(
        blacklist.verdict === "listed_critical"
            ? {
                  label: `Listed on ${plural(count.critical, "critical source")}`,
                  tone: "danger",
                  needsAttention: true,
              }
            : blacklist.verdict === "listed"
              ? {
                    label: `Listed on ${plural(count.listed, "source")}`,
                    tone: "warning",
                    needsAttention: true,
                }
              : blacklist.verdict === "inconclusive"
                ? { label: "Inconclusive", tone: "muted", needsAttention: false }
                : { label: "Not listed", tone: "success", needsAttention: false },
    );

    // The check's own line, so it still says what was found when folded.
    const checkStatus: CheckStatus = $derived(
        listed ? "fail" : blacklist.verdict === "inconclusive" ? "neutral" : "pass",
    );

    const unanswered = $derived(
        [
            count.errored > 0 ? `${count.errored} failed` : "",
            count.pending > 0 ? `${count.pending} pending` : "",
        ]
            .filter(Boolean)
            .join(", "),
    );

    const summary = $derived.by(() => {
        if (blacklist.verdict === "inconclusive") {
            if (count.enabled === 0) return "No source is enabled on this instance";
            if (count.pending > 0) {
                return `${plural(count.pending, "source")} still loading, try again in a few minutes`;
            }
            return "No source answered, try again later";
        }
        const tail = unanswered ? `, ${unanswered}` : "";
        return listed
            ? `Listed on ${count.listed} of ${plural(count.answered, "source")}${tail}`
            : `Not listed by ${plural(count.answered, "source")}${tail}`;
    });

    function severityRank(sev: string | undefined): number {
        switch (sev) {
            case "crit":
                return 0;
            case "warn":
                return 1;
            case "info":
                return 2;
            default:
                return 3;
        }
    }

    // The backend says how each source counts toward the verdict; the card
    // only orders and labels them.
    function statusRank(s: DomainBlacklistSourceResult["status"]): number {
        switch (s) {
            case "listed":
                return 0;
            case "errored":
                return 1;
            case "pending":
                return 2;
            case "clean":
                return 3;
            case "informational":
                return 4;
        }
    }

    const sorted = $derived(
        [...blacklist.results].sort((a, b) => {
            const ra = statusRank(a.status);
            const rb = statusRank(b.status);
            if (ra !== rb) return ra - rb;
            if (a.status === "listed") {
                const r = severityRank(a.severity) - severityRank(b.severity);
                if (r !== 0) return r;
            }
            return a.source_name.localeCompare(b.source_name);
        }),
    );

    interface Verdict {
        label: string;
        icon: string;
        /** Tone of the pill, solid for what calls for attention, subtle otherwise. */
        badge: string;
        /** Class of the whole row, tinted when the source names the domain. */
        row?: string;
        detail: string;
    }

    const subtle = (tone: string) =>
        `bg-${tone}-subtle text-${tone}-emphasis border-${tone}-subtle`;
    const solid = (tone: string) => `text-bg-${tone} border-${tone}`;

    /** What one source said about the domain, in a word a reader can act on. */
    function verdictOf(r: DomainBlacklistSourceResult): Verdict {
        const reason = r.error ?? r.reasons?.[0] ?? "";
        switch (r.status) {
            case "errored":
                return {
                    label: r.blocked_query ? "Blocked" : "No answer",
                    icon: "bi-question-lg",
                    badge: subtle("secondary"),
                    detail: r.blocked_query
                        ? "This list refuses the instance's resolver: it does not count"
                        : `${reason || "The lookup failed"}: it does not count`,
                };
            case "pending":
                return {
                    label: "Pending",
                    icon: "bi-hourglass-split",
                    badge: subtle("secondary"),
                    detail: "Data still loading, available at the next check",
                };
            case "listed": {
                const minor = r.severity === "warn" || r.severity === "info";
                return {
                    label: "Listed",
                    icon: minor ? "bi-exclamation-lg" : "bi-x-lg",
                    badge: solid(minor ? "warning" : "danger"),
                    row: minor ? "minor" : "listed",
                    detail: reason,
                };
            }
            case "informational":
                // Web ad and tracker lists, which mail filters do not use
                return r.listed
                    ? {
                          label: "Web only",
                          icon: "bi-info-lg",
                          badge: subtle("info"),
                          detail: "Web ad and tracker list, not used by mail filters: not scored",
                      }
                    : { label: "Clean", icon: "bi-check-lg", badge: subtle("success"), detail: "" };
            case "clean":
                return {
                    label: "Clean",
                    icon: "bi-check-lg",
                    badge: subtle("success"),
                    detail: "",
                };
        }
    }

    const rowKey = (r: DomainBlacklistSourceResult) => `${r.source_id}::${r.subject ?? ""}`;

    /** The reference when it is the source's site: the name links to it, no click spent. */
    const referenceUrl = (r: DomainBlacklistSourceResult) =>
        r.reference && /^https?:\/\//.test(r.reference) ? r.reference : undefined;

    /** More to read than the line the row already shows. */
    function hasDetails(r: DomainBlacklistSourceResult): boolean {
        return (
            (r.reasons?.length ?? 0) > 1 ||
            (r.evidence?.length ?? 0) > 0 ||
            (!!r.reference && !referenceUrl(r))
        );
    }

    const registered = $derived(
        blacklist.registered_domain && blacklist.registered_domain !== domain
            ? blacklist.registered_domain
            : undefined,
    );
</script>

<!-- Every source on one row of the same columns, its verdict first and in words: what names
     the domain stands out by its colour, not by a layout of its own. -->
{#snippet sources(results: DomainBlacklistSourceResult[])}
    <ul class="sources list-unstyled small mb-2">
        {#each results as r (rowKey(r))}
            {@const verdict = verdictOf(r)}
            <li class={verdict.row}>
                <span
                    class={[
                        "verdict badge rounded-pill border d-inline-flex align-items-center justify-content-center gap-1",
                        verdict.badge,
                    ]}
                >
                    <i class="bi {verdict.icon}" aria-hidden="true"></i>{verdict.label}
                </span>
                <span class="name" title={r.subject ? `DNS zone ${r.subject}` : undefined}>
                    {#if referenceUrl(r)}
                        <!-- eslint-disable svelte/no-navigation-without-resolve -- the list's own site -->
                        <a
                            href={referenceUrl(r)}
                            target="_blank"
                            rel="noopener noreferrer"
                            class="text-reset"
                            title="About this source">{r.source_name}</a
                        >
                        <!-- eslint-enable svelte/no-navigation-without-resolve -->
                    {:else}
                        {r.source_name}
                    {/if}
                </span>
                <span class="detail text-body-secondary">{verdict.detail}</span>
                <span class="action">
                    {#if r.lookup_url}
                        <!-- eslint-disable svelte/no-navigation-without-resolve -- the list's own site -->
                        <a href={r.lookup_url} target="_blank" rel="noopener noreferrer">
                            Look up
                            <i class="bi bi-box-arrow-up-right" aria-hidden="true"></i>
                        </a>
                        <!-- eslint-enable svelte/no-navigation-without-resolve -->
                    {/if}
                </span>
                {#if hasDetails(r)}
                    <details class="passed-items more" open={r.status === "listed"}>
                        <summary>Details</summary>
                        {#if r.reasons && r.reasons.length > 1}
                            <ul class="mb-2 mt-1">
                                {#each r.reasons as reason (reason)}
                                    <li>{reason}</li>
                                {/each}
                            </ul>
                        {/if}
                        {#if r.evidence && r.evidence.length > 0}
                            <dl class="check-facts mt-1">
                                {#each r.evidence as ev, i (i)}
                                    <dt>{ev.label}</dt>
                                    <dd>
                                        <code>{ev.value}</code>
                                        {#if ev.status}
                                            <span class="badge bg-light text-body ms-1"
                                                >{ev.status}</span
                                            >
                                        {/if}
                                    </dd>
                                {/each}
                            </dl>
                        {/if}
                        {#if r.reference && !referenceUrl(r)}
                            <p class="check-about">Reference: {r.reference}</p>
                        {/if}
                    </details>
                {/if}
            </li>
        {/each}
    </ul>
{/snippet}

<ReportSection
    id="reputation-details"
    class={className}
    title="Domain Reputation"
    icon="shield-shaded"
    grade={blacklist.grade}
    score={blacklist.score}
    {status}
    open={open ?? status.needsAttention}
>
    <div class="card-body">
        <CheckList title="Sender domain" subject={domain || blacklist.registered_domain}>
            {#snippet aside()}
                {#if registered && domain}
                    <span class="registered small ms-auto">
                        Queried as <span class="font-monospace">{registered}</span>, its registered
                        domain
                    </span>
                {/if}
            {/snippet}

            <CheckCard
                id="blacklist-sources"
                title="Domain blacklists"
                tag="DNSBL"
                status={checkStatus}
                {summary}
                docs={[docs.dnsbl]}
                rows={{ issues: blacklist.issues?.sources, one: "source", many: "sources" }}
                open
            >
                <div class="card-body">
                    {@render sources(sorted)}
                    <p class="check-about">
                        Domain blacklists name domains seen in spam or phishing. Receivers look up
                        the domain of the From address, and of the links in the message: a listing
                        on a major one can be enough to have it filtered.
                    </p>
                </div>
            </CheckCard>
        </CheckList>
    </div>
</ReportSection>

<style>
    .registered {
        text-transform: none;
        letter-spacing: normal;
    }

    /* A verdict in words, the same width on every row so the names line up after it. */
    .verdict {
        min-width: 6.5rem;
        font-size: 0.75rem;
    }

    /* One grid for the whole list, each row on its columns: verdict, source, reason, action. */
    .sources {
        display: grid;
        grid-template-columns: auto max-content 1fr auto;
        column-gap: 0.75rem;
        row-gap: 0.125rem;

        li {
            grid-column: 1 / -1;
            display: grid;
            grid-template-columns: subgrid;
            align-items: center;
            padding: 0.25rem 0.5rem;
            border-radius: var(--hd-radius-md, 0.375rem);

            > :not(.verdict) {
                justify-self: start;
            }

            &.listed {
                background: var(--bs-danger-bg-subtle);
            }

            &.minor {
                background: var(--bs-warning-bg-subtle);
            }
        }

        .more {
            grid-column: 2 / -1;
        }

        /* Narrow: the reason and the action go under the source's name. */
        @media (max-width: 575.98px) {
            grid-template-columns: auto 1fr;

            .detail,
            .action,
            .more {
                grid-column: 2;
            }

            .detail:empty,
            .action:empty {
                display: none;
            }
        }
    }
</style>
