<script lang="ts">
    import type { DmarcRecord, HeaderAnalysis, HeaderCheck, Issue } from "#lib/api/types.gen.js";
    import { docs, headerDocLinks } from "#lib/docs.js";
    import type { SectionStatus } from "#lib/sections.js";
    import CheckCard from "./CheckCard.svelte";
    import CheckList from "./CheckList.svelte";
    import IssueNote from "./IssueNote.svelte";
    import ReportSection from "./ReportSection.svelte";

    interface Props {
        dmarcRecord?: DmarcRecord;
        headerAnalysis: HeaderAnalysis;
        headerGrade?: string;
        headerScore?: number;
        status?: SectionStatus;
        open?: boolean;
    }

    let {
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

    type Relation = "same" | "organizational" | "unrelated";

    /** How one identity relates to the From domain, which is all DMARC alignment asks. */
    interface Identity {
        label: string;
        /** The DMARC tag setting how closely this identity has to match. */
        tag: "aspf" | "adkim";
        mode?: string;
        domain: string;
        relation: Relation;
        /** Whether DMARC counts it: a policy asking for strict alignment wants the same domain. */
        counts: boolean;
    }

    const alignment = $derived(headerAnalysis.domain_alignment);

    function relationOf(domain: string, orgDomain?: string): Relation {
        const same = (a?: string, b?: string) => !!a && !!b && a.toLowerCase() === b.toLowerCase();
        if (same(domain, alignment?.from_domain)) return "same";
        if (same(orgDomain, alignment?.from_org_domain)) return "organizational";
        return "unrelated";
    }

    const identities = $derived.by<Identity[]>(() => {
        if (!alignment) return [];
        const found: Omit<Identity, "counts">[] = [];
        if (alignment.return_path_domain) {
            found.push({
                label: "Return-Path (SPF)",
                tag: "aspf",
                mode: dmarcRecord?.spf_alignment,
                domain: alignment.return_path_domain,
                relation: relationOf(
                    alignment.return_path_domain,
                    alignment.return_path_org_domain,
                ),
            });
        }
        for (const dkim of alignment.dkim_domains ?? []) {
            found.push({
                label: "DKIM signature",
                tag: "adkim",
                mode: dmarcRecord?.dkim_alignment,
                domain: dkim.domain,
                relation: relationOf(dkim.domain, dkim.org_domain),
            });
        }
        return found.map((identity) => ({
            ...identity,
            counts:
                identity.relation === "same" ||
                (identity.relation === "organizational" && identity.mode !== "strict"),
        }));
    });

    const relationText: Record<Relation, string> = {
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
                    .filter((i) => i.counts)
                    .map((i) => (i.tag === "aspf" ? "the Return-Path" : "DKIM")),
            ),
        ];
        return through.length > 0
            ? `Aligned through ${through.join(" and ")}`
            : "Neither the Return-Path nor DKIM is aligned";
    });

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
                        : identities.some((i) => i.counts)
                          ? "pass"
                          : "fail"}
                    summary={alignmentSummary}
                    docs={[docs.dmarcAlignment]}
                    issues={headerAnalysis.issues?.domain_alignment}
                >
                    <div class="card-body">
                        {#if identities.length > 0}
                            <dl class="check-facts">
                                {#each identities as identity, i (i)}
                                    <dt>{identity.label}</dt>
                                    <dd>
                                        <code>{identity.domain}</code>
                                        <span class="small text-body-secondary ms-1 text-nowrap">
                                            <i
                                                class="bi me-1 {identity.counts
                                                    ? 'bi-check-circle-fill text-success'
                                                    : 'bi-x-circle text-danger'}"
                                                aria-hidden="true"
                                            ></i>{relationText[identity.relation]}
                                        </span>
                                        {#if identity.relation === "organizational" && identity.mode === "strict"}
                                            <div class="small text-danger">
                                                Your DMARC policy sets {identity.tag}=s: only the
                                                same domain counts.
                                            </div>
                                        {/if}
                                    </dd>
                                {/each}
                            </dl>
                        {/if}
                        <p class="check-about">
                            DMARC passes when SPF or DKIM passes for a domain aligned with the From
                            domain{alignment.from_domain ? ` (${alignment.from_domain})` : ""}: the
                            same domain or, unless the policy asks for strict alignment, one sharing
                            its organizational domain{alignment.from_org_domain &&
                            alignment.from_org_domain !== alignment.from_domain
                                ? ` (${alignment.from_org_domain})`
                                : ""}. One aligned identity is enough.
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
