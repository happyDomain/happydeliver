<script lang="ts">
    import { resolve } from "$app/paths";
    import { page } from "$app/state";

    import type { BlacklistCheck, Issue } from "#lib/api/types.gen.js";
    import { docs, rblLookupLink } from "#lib/docs.js";
    import type { SectionStatus } from "#lib/sections.js";
    import CheckCard from "./CheckCard.svelte";
    import CheckList from "./CheckList.svelte";
    import ReportSection from "./ReportSection.svelte";

    interface Props {
        blacklists: Record<string, BlacklistCheck[]>;
        /** The DNS whitelists checked for the same addresses, which the grade also reads. */
        whitelists?: Record<string, BlacklistCheck[]>;
        blacklistGrade?: string;
        blacklistScore?: number;
        /** What the analyser found to change, by address. */
        issues?: Record<string, Issue[]>;
        status?: SectionStatus;
        open?: boolean;
    }

    let {
        blacklists,
        whitelists,
        blacklistGrade,
        blacklistScore,
        issues,
        status,
        open = true,
    }: Props = $props();

    /** Anchor of the listings of one address, which the section shows apart. */
    const rblAnchor = (ip: string) => `rbl-${ip}`;

    const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

    // A clean result is the expected one: what a reader needs is the lists that do name the
    // address, each with what to do about it, then those that could not tell.
    const ordered = (checks: BlacklistCheck[]) => [
        ...checks.filter((c) => c.listed),
        ...checks.filter((c) => !c.listed && c.error),
        ...checks.filter((c) => !c.listed && !c.error),
    ];

    const addresses = $derived(
        [...new Set([...Object.keys(blacklists), ...Object.keys(whitelists ?? {})])].map((ip) => {
            const rbls = blacklists[ip] ?? [];
            const dnswls = whitelists?.[ip];
            const listed = rbls.filter((c) => c.listed);
            const own = listed.filter((c) => !c.informational);
            const errored = rbls.filter((c) => !c.listed && c.error);
            const answered = rbls.length - errored.length;
            const vouching = (dnswls ?? []).filter((c) => c.listed);

            return {
                ip,
                rbls: ordered(rbls),
                listed,
                summary:
                    own.length > 0
                        ? `Listed on ${own.length} of ${answered} lists`
                        : listed.length > 0
                          ? `Only network-wide lists name it (${listed.length} of ${answered})`
                          : `Clean on ${plural(answered, "list")}` +
                            (errored.length > 0 ? `, ${errored.length} did not answer` : ""),
                dnswls: dnswls && ordered(dnswls),
                vouching,
            };
        }),
    );

    interface Verdict {
        label: string;
        icon: string;
        /** Tone of the pill, solid for what calls for attention, subtle otherwise. */
        badge: string;
        /** Class of the whole row, tinted when the list names the address. */
        row?: string;
        detail: string;
        title?: string;
    }

    const subtle = (tone: string) =>
        `bg-${tone}-subtle text-${tone}-emphasis border-${tone}-subtle`;
    const solid = (tone: string) => `text-bg-${tone} border-${tone}`;

    /** What one list said about the address, in a word a reader can act on. */
    function verdictOf(check: BlacklistCheck, whitelist: boolean): Verdict {
        const answered = check.response ? `Answered ${check.response}` : "";
        if (check.error && !check.listed) {
            return {
                label: "No answer",
                icon: "bi-question-lg",
                badge: subtle("secondary"),
                detail: "The lookup failed: it does not count",
                title: check.error,
            };
        }
        if (whitelist) {
            return check.listed
                ? {
                      label: "Vouches",
                      icon: "bi-check-lg",
                      badge: solid("success"),
                      row: "vouching",
                      detail: answered,
                  }
                : { label: "Not listed", icon: "bi-dash", badge: subtle("secondary"), detail: "" };
        }
        if (!check.listed) {
            return { label: "Clean", icon: "bi-check-lg", badge: subtle("success"), detail: "" };
        }
        if (check.informational) {
            return {
                label: "Network",
                icon: "bi-exclamation-lg",
                badge: solid("warning"),
                row: "network",
                detail: `${answered ? `${answered}: ` : ""}lists the whole range, a flat penalty`,
                title: "This list covers whole address ranges or providers: few receivers use it, and the score only takes a flat penalty for it",
            };
        }
        return {
            label: "Listed",
            icon: "bi-x-lg",
            badge: solid("danger"),
            row: "listed",
            detail: answered,
        };
    }

    // On the page dedicated to one address, a link to check that address again goes nowhere.
    const onAddressPage = $derived(page.route.id === "/blacklist/[ip]");
</script>

<!-- Every list on one row of the same columns, its verdict first and in words: what names
     the address stands out by its colour, not by a layout of its own. -->
{#snippet lists(checks: BlacklistCheck[], whitelist: boolean)}
    <ul class="lists list-unstyled small mb-2">
        {#each checks as check (check.rbl)}
            {@const verdict = verdictOf(check, whitelist)}
            {@const lookup = !whitelist && check.listed ? rblLookupLink(check.rbl) : undefined}
            <li class={verdict.row}>
                <span
                    class={[
                        "verdict badge rounded-pill border d-inline-flex align-items-center justify-content-center gap-1",
                        verdict.badge,
                    ]}
                    title={verdict.title}
                >
                    <i class="bi {verdict.icon}" aria-hidden="true"></i>{verdict.label}
                </span>
                <span class="font-monospace">{check.rbl}</span>
                <span class="detail text-body-secondary" title={check.error}>{verdict.detail}</span>
                <span class="action">
                    {#if lookup}
                        <!-- eslint-disable svelte/no-navigation-without-resolve -- the list's own site -->
                        <a href={lookup.url} target="_blank" rel="noopener noreferrer">
                            How to get delisted
                            <i class="bi bi-box-arrow-up-right" aria-hidden="true"></i>
                        </a>
                        <!-- eslint-enable svelte/no-navigation-without-resolve -->
                    {/if}
                </span>
            </li>
        {/each}
    </ul>
{/snippet}

<ReportSection
    id="rbl-details"
    title="IP Reputation"
    icon="shield-exclamation"
    grade={blacklistGrade}
    score={blacklistScore}
    {status}
    {open}
>
    <div class="card-body">
        {#each addresses as address (address.ip)}
            <CheckList title="Sending address" subject={address.ip}>
                {#snippet aside()}
                    {#if !onAddressPage}
                        <a
                            class="check-again small ms-auto"
                            href={resolve("/blacklist/[ip]", { ip: address.ip })}
                        >
                            Check again<i class="bi bi-arrow-right-short" aria-hidden="true"></i>
                        </a>
                    {/if}
                {/snippet}

                {#if address.rbls.length > 0}
                    <CheckCard
                        id={rblAnchor(address.ip)}
                        title="Blacklists"
                        tag="DNSBL"
                        status={address.listed.length > 0 ? "fail" : "pass"}
                        summary={address.summary}
                        docs={[docs.dnsbl]}
                        rows={{ issues: issues?.[address.ip], one: "list", many: "lists" }}
                    >
                        <div class="card-body">
                            {@render lists(address.rbls, false)}
                            <p class="check-about">
                                Blacklists name addresses that sent spam or were taken over.
                                Receivers look them up while your message is being delivered: a
                                listing on a major one is enough to be refused.
                            </p>
                        </div>
                    </CheckCard>
                {/if}

                {#if address.dnswls}
                    <CheckCard
                        title="Whitelists"
                        tag="DNSWL"
                        status={address.vouching.length > 0 ? "pass" : "improve"}
                        summary={address.vouching.length > 0
                            ? `Vouched for by ${address.vouching.map((c) => c.rbl).join(", ")}`
                            : `Not on any of the ${plural(address.dnswls.length, "whitelist")}`}
                    >
                        <div class="card-body">
                            {@render lists(address.dnswls, true)}
                            <p class="check-about">
                                Whitelists vouch for senders they trust. Not being on one costs no
                                points, but a report only grades an address A+ when a whitelist
                                vouches for it: without one, the grade stops at A. Most take
                                requests from senders whose mail has a clean history.
                            </p>
                        </div>
                    </CheckCard>
                {/if}
            </CheckList>
        {/each}
    </div>
</ReportSection>

<style>
    .check-again {
        text-transform: none;
        letter-spacing: normal;
    }

    /* A verdict in words, the same width on every row so the names line up after it. */
    .verdict {
        min-width: 6.5rem;
        font-size: 0.75rem;
    }

    /* One grid for the whole list, each row on its columns: verdict, list, answer, action. */
    .lists {
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

            &.network {
                background: var(--bs-warning-bg-subtle);
            }

            &.vouching {
                background: var(--bs-success-bg-subtle);
            }
        }

        .font-monospace {
            font-size: 0.875rem;
        }

        /* Narrow: the answer and the action go under the list's name. */
        @media (max-width: 575.98px) {
            grid-template-columns: auto 1fr;

            .detail,
            .action {
                grid-column: 2;
            }

            .detail:empty,
            .action:empty {
                display: none;
            }
        }
    }
</style>
