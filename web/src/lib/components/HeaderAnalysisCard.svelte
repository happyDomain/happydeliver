<script lang="ts">
    import type {
        AuthenticationResults,
        DmarcRecord,
        HeaderAnalysis,
        HeaderCheck,
        Issue,
    } from "#lib/api/types.gen.js";
    import {
        alignmentIdentities,
        sameDomain,
        verdictStatus,
        type AlignmentIdentity,
        type DomainRelation,
    } from "#lib/authentication.js";
    import { docs, headerDocLinks } from "#lib/docs.js";
    import type { SectionStatus } from "#lib/sections.js";
    import CheckCard, { statusTones } from "./CheckCard.svelte";
    import CheckList from "./CheckList.svelte";
    import FactRow from "./FactRow.svelte";
    import IssueNote from "./IssueNote.svelte";
    import ReportSection from "./ReportSection.svelte";
    import VerdictFacts from "./VerdictFacts.svelte";

    interface Props {
        /** The verdicts of the identities compared: alignment only counts on a pass. */
        authentication?: AuthenticationResults;
        dmarcRecord?: DmarcRecord;
        headerAnalysis: HeaderAnalysis;
        headerGrade?: string;
        headerScore?: number;
        status?: SectionStatus;
        open?: boolean;
    }

    let {
        authentication,
        dmarcRecord,
        headerAnalysis,
        headerGrade,
        headerScore,
        status,
        open = true,
    }: Props = $props();

    /** Anchor of the line of a header, by its name as the analysis keys it. */
    const headerAnchor = (name: string) => `header-${name.toLowerCase()}`;

    // Each issue about a header is shown on its line; one about a header the analysis has no
    // check for, on the section.
    const headerIssues = $derived(headerAnalysis.issues?.headers ?? []);
    const issuesOf = (name: string) =>
        headerIssues.filter((issue) => issue.location?.toLowerCase() === name);
    const unplaced = $derived(
        headerIssues.filter(
            (issue) => !headerAnalysis.headers?.[issue.location?.toLowerCase() ?? ""],
        ),
    );

    // ─── Alignment ─────────────────────────────────────────────────────────────

    const alignment = $derived(headerAnalysis.domain_alignment);
    const identities = $derived(alignmentIdentities(alignment, authentication, dmarcRecord));

    const relationText: Record<DomainRelation, string> = {
        same: "same domain",
        organizational: "same organizational domain",
        unrelated: "unrelated domain",
    };

    const alignmentSummary = $derived.by(() => {
        if (!alignment) return undefined;
        if (identities.length === 0) return "No Return-Path nor DKIM signature to compare";
        const through = [
            ...new Set(
                identities
                    .filter((i) => i.aligned)
                    .map((i) => (i.tag === "aspf" ? "the Return-Path" : "DKIM")),
            ),
        ];
        return through.length > 0
            ? `Aligned through ${through.join(" and ")}`
            : "Neither the Return-Path nor DKIM is aligned";
    });

    /** What DMARC makes of an identity, said in the heading of its block. */
    function outcome(identity: AlignmentIdentity): { icon: string; text: string } {
        if (identity.counts) {
            return {
                icon: "bi-check-circle-fill text-success",
                text: "aligned and passing: enough for DMARC",
            };
        }
        if (identity.aligned) {
            return {
                icon: "bi-exclamation-triangle-fill text-warning",
                text: identity.verdict
                    ? `aligned, but ${identity.mechanism} does not pass`
                    : `aligned, but no ${identity.mechanism} verdict was reported`,
            };
        }
        return { icon: "bi-x-circle-fill text-danger", text: "not aligned: DMARC ignores it" };
    }

    /** Why an identity is aligned or not, in the terms of its relation and of the mode. */
    function alignmentReason(identity: AlignmentIdentity): string {
        switch (identity.relation) {
            case "same":
                return "It is the From domain itself: aligned in both modes.";
            case "organizational":
                return identity.mode === "strict"
                    ? `It shares the organizational domain of the From domain, but the DMARC record sets ${identity.tag}=s, which asks for the From domain itself.`
                    : "It shares the organizational domain of the From domain, which relaxed alignment accepts.";
            default:
                return "It does not share the organizational domain of the From domain: it cannot be aligned, whatever the mode.";
        }
    }

    // ─── Headers ───────────────────────────────────────────────────────────────

    /** The name as written in a message, from the lower-case key the analysis uses. */
    function displayName(name: string): string {
        const words: Record<string, string> = { id: "ID", mime: "MIME", dkim: "DKIM" };
        return name
            .split("-")
            .map((w) => words[w] ?? w.charAt(0).toUpperCase() + w.slice(1))
            .join("-");
    }

    type Importance = NonNullable<HeaderCheck["importance"]>;

    /** How the headers are checked together, by how much the analysis expects them. */
    const groups: {
        importance: Importance;
        title: string;
        tag?: string;
        about: string;
        /** Whether absence is the expected state, which leaves the check ungraded. */
        optional?: boolean;
    }[] = [
        {
            importance: "required",
            title: "Required headers",
            tag: "RFC 5322",
            about: "Every message identifies its sender, its recipients, when it was written and itself; filters distrust one that does not.",
        },
        {
            importance: "recommended",
            title: "Recommended headers",
            about: "Not mandatory, but expected: their absence or a malformed value makes a message look hand-crafted.",
        },
        {
            importance: "optional",
            title: "Other headers",
            about: "Headers the analysis looked at without expecting them.",
            optional: true,
        },
        {
            importance: "newsletter",
            title: "Unsubscribe headers",
            tag: "Newsletters",
            about: "Bulk senders must let recipients unsubscribe in one click from their mailbox; personal and transactional mail does without.",
            optional: true,
        },
    ];

    // The order a message usually writes them in, so the list reads like its top
    const headerOrder = [
        "from",
        "reply-to",
        "to",
        "subject",
        "date",
        "message-id",
        "mime-version",
        "list-unsubscribe",
        "list-unsubscribe-post",
    ];
    const rank = (name: string) => {
        const i = headerOrder.indexOf(name);
        return i < 0 ? headerOrder.length : i;
    };

    interface HeaderRow {
        name: string;
        check: HeaderCheck;
        issues: Issue[];
    }

    const headerGroups = $derived(
        groups
            .map((group) => {
                const rows: HeaderRow[] = Object.entries(headerAnalysis.headers ?? {})
                    .filter(([, check]) => (check.importance ?? "optional") === group.importance)
                    .sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b))
                    .map(([name, check]) => ({ name, check, issues: issuesOf(name) }));
                const present = rows.filter((r) => r.check.present);
                const flagged = rows.filter((r) => r.issues.length > 0);
                const summary =
                    flagged.length > 0
                        ? `${flagged.map((r) => displayName(r.name)).join(", ")} to check`
                        : group.optional && present.length === 0
                          ? "None present"
                          : group.optional
                            ? `${present.map((r) => displayName(r.name)).join(", ")} present`
                            : rows.length > 1
                              ? `All ${rows.length} present and well-formed`
                              : "Present and well-formed";
                return {
                    ...group,
                    rows,
                    summary,
                    issues: flagged.flatMap((r) => r.issues),
                    docs: rows.flatMap((r) => headerDocLinks(r.name)),
                    status: (group.optional && present.length === 0 ? "neutral" : "pass") as
                        "neutral" | "pass",
                };
            })
            .filter((group) => group.rows.length > 0),
    );
</script>

<ReportSection
    id="header-details"
    title="Header Analysis"
    icon="list-ul"
    grade={headerGrade}
    score={headerScore}
    {status}
    {open}
>
    <div class="card-body">
        {#each unplaced as issue, i (i)}
            <IssueNote {issue} />
        {/each}

        {#if alignment}
            <CheckList title="Sender identity" subject={alignment.from_domain}>
                <CheckCard
                    id="domain-alignment"
                    title="Domain Alignment"
                    tag="DMARC"
                    status={identities.length === 0
                        ? "neutral"
                        : identities.some((i) => i.aligned)
                          ? "pass"
                          : "fail"}
                    summary={alignmentSummary}
                    docs={[docs.dmarcAlignment]}
                    issues={headerAnalysis.issues?.domain_alignment}
                >
                    <div class="card-body">
                        <VerdictFacts title="The From domain, which each identity is held against">
                            {#if headerAnalysis.headers?.from?.value}
                                <FactRow
                                    label="From"
                                    value={headerAnalysis.headers.from.value}
                                    mono
                                />
                            {/if}
                            {#if alignment.from_domain}
                                <FactRow label="Domain" value={alignment.from_domain} mono />
                            {/if}
                            {#if alignment.from_org_domain}
                                <FactRow label="Organizational domain">
                                    <span class="font-monospace">{alignment.from_org_domain}</span>
                                    <span class="fact-note"
                                        >The domain registered right under its public suffix (.com,
                                        .co.uk…): the one its owner bought.</span
                                    >
                                </FactRow>
                            {/if}
                        </VerdictFacts>

                        {#if identities.length > 0}
                            <p class="small text-body-secondary mb-0">
                                {identities.length === 1
                                    ? "DMARC passes on the identity below if it is"
                                    : `DMARC passes on any of the ${identities.length} identities below that is`}
                                both aligned with the From domain and passing:
                            </p>
                        {/if}

                        {#each identities as identity, i (i)}
                            {@const result = outcome(identity)}
                            <h6
                                class="alignment-identity d-flex flex-wrap align-items-baseline column-gap-2 mb-1"
                            >
                                <i class="bi {result.icon}" aria-hidden="true"></i>
                                <span class="fw-semibold"
                                    >{identity.mechanism === "SPF"
                                        ? "SPF, through the Return-Path"
                                        : `DKIM signature by ${identity.domain}`}</span
                                >
                                <span class="small fw-normal text-body-secondary"
                                    >{result.text}</span
                                >
                            </h6>
                            <VerdictFacts
                                title="Found in the message"
                                links={identity.mechanism === "SPF"
                                    ? [
                                          { href: "#authentication-spf", label: "SPF verdict" },
                                          { href: "#dns-spf", label: "SPF record" },
                                      ]
                                    : [
                                          { href: "#authentication-dkim", label: "DKIM verdicts" },
                                          { href: "#dns-dkim", label: "DKIM records" },
                                      ]}
                            >
                                {#if identity.mechanism === "SPF"}
                                    {#if identity.address}
                                        <FactRow
                                            label="Return-Path"
                                            value={identity.address}
                                            mono
                                        />
                                    {/if}
                                    <FactRow label="Domain" value={identity.domain} mono />
                                {:else}
                                    <FactRow
                                        label="Signing domain (d=)"
                                        value={identity.domain}
                                        mono
                                    />
                                    {#if identity.selector}
                                        <FactRow
                                            label="Selector (s=)"
                                            value={identity.selector}
                                            mono
                                        />
                                    {/if}
                                {/if}
                                {#if identity.orgDomain}
                                    {@const sameOrg = sameDomain(
                                        identity.orgDomain,
                                        alignment.from_org_domain,
                                    )}
                                    <FactRow
                                        label="Organizational domain"
                                        value={identity.orgDomain}
                                        mono
                                        ok={alignment.from_org_domain ? sameOrg : undefined}
                                        okLabel={sameOrg
                                            ? "the From domain's"
                                            : `not ${alignment.from_org_domain}`}
                                    />
                                {/if}
                                <FactRow label="Alignment">
                                    <span
                                        class="fw-semibold {identity.aligned
                                            ? 'text-success'
                                            : 'text-danger'}"
                                        >{identity.aligned ? "aligned" : "not aligned"}</span
                                    >
                                    <span class="text-body-secondary"
                                        >({relationText[identity.relation]})</span
                                    >
                                    <span class="fact-note">{alignmentReason(identity)}</span>
                                </FactRow>
                                {#snippet help()}
                                    <FactRow label="{identity.mechanism} verdict">
                                        {#if identity.verdict}
                                            <span
                                                class="fw-semibold {statusTones[
                                                    verdictStatus(identity.verdict.result, true)
                                                ]}">{identity.verdict.result}</span
                                            >
                                        {:else}
                                            <span class="text-body-secondary">not reported</span>
                                        {/if}
                                        <span class="fact-note">
                                            {#if identity.counts}
                                                Aligned and passing: DMARC passes on this identity
                                                alone.
                                            {:else if identity.aligned}
                                                Aligned, so DMARC would count it, if it passed.
                                            {:else}
                                                Whatever it is, DMARC does not count it: the domain
                                                is not aligned.
                                            {/if}
                                        </span>
                                    </FactRow>
                                    <FactRow label="Alignment mode">
                                        <span class="font-monospace"
                                            >{identity.tag}={identity.mode === "strict"
                                                ? "s"
                                                : "r"}</span
                                        >
                                        <span class="text-body-secondary"
                                            >({identity.mode === "strict"
                                                ? "strict"
                                                : "relaxed"}{dmarcRecord
                                                ? ""
                                                : ", by default"})</span
                                        >
                                        <span class="fact-note">
                                            {#if !dmarcRecord}
                                                The From domain publishes no DMARC record: no policy
                                                applies to what fails.
                                            {:else if identity.mode === "strict"}
                                                Only the From domain itself is aligned.
                                            {:else}
                                                Any domain sharing the organizational domain of the
                                                From domain is aligned.
                                            {/if}
                                        </span>
                                    </FactRow>
                                {/snippet}
                            </VerdictFacts>
                        {/each}

                        <p class="check-about">
                            DMARC ties SPF and DKIM to the From address, the one the recipient sees:
                            it passes when one of them passes for a domain aligned with the From
                            domain. Relaxed alignment, the default, accepts any domain sharing its
                            organizational domain (news.example.com for example.com); strict
                            alignment, set by aspf=s or adkim=s, only the From domain itself. One
                            identity aligned and passing is enough.
                        </p>
                    </div>
                </CheckCard>
            </CheckList>
        {/if}

        {#if headerGroups.length > 0}
            <CheckList title="Message headers">
                {#each headerGroups as group (group.importance)}
                    <CheckCard
                        title={group.title}
                        tag={group.tag}
                        status={group.status}
                        summary={group.summary}
                        docs={group.docs}
                        issues={group.issues}
                    >
                        <div class="card-body">
                            <!-- As they head the message: one line each, its name first -->
                            <ul class="header-lines">
                                {#each group.rows as { name, check, issues: flagged } (name)}
                                    {@const tone = flagged.some(
                                        (i) => i.severity === "critical" || i.severity === "high",
                                    )
                                        ? "danger"
                                        : flagged.length > 0
                                          ? "warning"
                                          : undefined}
                                    <li id={headerAnchor(name)} class={tone}>
                                        <span class="flag">
                                            {#if tone}
                                                <i
                                                    class="bi bi-exclamation-triangle-fill text-{tone}"
                                                    role="img"
                                                    aria-label="Reported"
                                                ></i>
                                            {/if}
                                        </span>
                                        <span class="fw-semibold text-nowrap"
                                            >{displayName(name)}:</span
                                        >
                                        {#if check.present}
                                            <span class="value">{check.value}</span>
                                        {:else}
                                            <span
                                                class="value absent fst-italic {group.optional
                                                    ? ''
                                                    : 'text-danger'}">not present</span
                                            >
                                        {/if}
                                    </li>
                                {/each}
                            </ul>
                            <p class="check-about">{group.about}</p>
                        </div>
                    </CheckCard>
                {/each}
            </CheckList>
        {/if}
    </div>
</ReportSection>

<style>
    /* Each identity DMARC may rest on, apart from the others: what it says about one does
       not hold for the next. */
    .alignment-identity {
        margin-top: 1rem;
        padding-top: 0.75rem;
        border-top: 1px dashed var(--hd-border-1);
    }

    /* The headers as a message writes them, each line on the columns of the whole block:
       the flag of a reported one, the name, the value wrapping under itself. */
    .header-lines {
        display: grid;
        grid-template-columns: 1rem max-content 1fr;
        column-gap: 0.5rem;
        margin: 0 0 0.5rem;
        padding: 0;
        list-style: none;
        border: 1px solid var(--bs-border-color-translucent);
        border-radius: var(--hd-radius-md);
        font-family: var(--bs-font-monospace);
        font-size: 0.8125rem;
        overflow: hidden;

        li {
            --tone: transparent;
            grid-column: 1 / -1;
            display: grid;
            grid-template-columns: subgrid;
            padding: 0.375rem 0.75rem 0.375rem 0.5rem;
            background: color-mix(in srgb, var(--tone) 10%, transparent);

            /* As a hovered table row: over the tint of a reported one, not instead of it */
            &:hover {
                box-shadow: inset 0 0 0 9999px rgba(var(--bs-emphasis-color-rgb), 0.075);
            }

            & + li {
                border-top: 1px solid var(--bs-border-color-translucent);
            }

            &.warning {
                --tone: var(--bs-warning);
            }

            &.danger {
                --tone: var(--bs-danger);
            }
        }

        .value {
            min-width: 0;
            overflow-wrap: anywhere;
        }

        .absent {
            font-family: var(--bs-body-font-family);
            color: var(--hd-fg-3);
        }
    }
</style>
