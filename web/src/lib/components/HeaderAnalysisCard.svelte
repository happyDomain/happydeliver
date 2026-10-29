<script lang="ts">
    import { dmarcAlignment } from "#lib/alignment.js";
    import type { DmarcRecord, HeaderAnalysis, HeaderCheck } from "#lib/api/types.gen.js";
    import { docs, headerDocLinks, issueDocLinks } from "#lib/docs.js";
    import { compareBySeverity, issueLabel } from "#lib/issues.js";
    import type { SectionStatus } from "#lib/sections.js";
    import CheckCard from "./CheckCard.svelte";
    import DocLinks from "./DocLinks.svelte";
    import IssueAlert from "./IssueAlert.svelte";
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

    /** Anchor of a header issue, by its position in header_analysis.issues.headers. */
    const headerIssueAnchor = (index: number) => `header-issue-${index}`;

    // Gravest first, as in the content card. The alert's colour no longer competes with a
    // badge naming the level, so the order is what tells a reader where to start. Each keeps
    // its position in the API's list, which is what its anchor is made of.
    const issues = $derived(
        (headerAnalysis.issues?.headers ?? [])
            .map((issue, index) => ({ issue, index }))
            .sort((a, b) => compareBySeverity(a.issue, b.issue)),
    );

    // Each header's issues, by the name its row shows: the row points at them in the list.
    const issuesAt = $derived(
        issues.reduce((byName, entry) => {
            const name = entry.issue.location?.toLowerCase() ?? "";
            byName.set(name, [...(byName.get(name) ?? []), entry]);
            return byName;
        }, new Map<string, typeof issues>()),
    );

    const alignmentIssues = $derived(
        (headerAnalysis.issues?.domain_alignment ?? []).slice().sort(compareBySeverity),
    );

    const importanceOrder = { required: 0, recommended: 1, optional: 2, newsletter: 3 };

    // A header row has something to say when an expected header is missing, or a present one
    // is malformed. Everything else is the expected state and is folded away.
    function isProblem(name: string, check: HeaderCheck): boolean {
        if (issuesAt.has(name)) return true;
        if (check.present) return check.valid === false;
        return check.importance === "required" || check.importance === "recommended";
    }

    const headerRows = $derived(
        Object.entries(headerAnalysis.headers ?? {}).sort(
            ([, a], [, b]) =>
                importanceOrder[a.importance || "optional"] -
                importanceOrder[b.importance || "optional"],
        ),
    );
    const problemRows = $derived(headerRows.filter(([name, check]) => isProblem(name, check)));
    const fineRows = $derived(headerRows.filter(([name, check]) => !isProblem(name, check)));

    const alignment = $derived(headerAnalysis.domain_alignment);
    const alignmentSummary = $derived(
        alignment
            ? [
                  alignment.from_domain ? `From ${alignment.from_domain}` : undefined,
                  alignment.return_path_domain
                      ? `Return-Path ${alignment.return_path_domain}`
                      : undefined,
                  ...(alignment.dkim_domains ?? []).map((d) => `DKIM ${d.domain}`),
              ]
                  .filter(Boolean)
                  .join(", ")
            : undefined,
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
        {#if issues.length > 0}
            <div class="mb-3">
                <h5>Issues</h5>
                {#each issues as { issue, index } (index)}
                    <IssueAlert
                        id={headerIssueAnchor(index)}
                        title={issueLabel(issue.type)}
                        severity={issue.severity}
                        message={issue.message}
                        advice={issue.advice}
                        docs={headerDocLinks(issue.location ?? "")}
                    />
                {/each}
            </div>
        {/if}

        {#if headerAnalysis.domain_alignment}
            {@const alignmentLevel = dmarcAlignment(headerAnalysis.domain_alignment, dmarcRecord)}
            {@const spfStrictAligned =
                headerAnalysis.domain_alignment.from_domain ===
                headerAnalysis.domain_alignment.return_path_domain}
            {@const spfRelaxedAligned =
                headerAnalysis.domain_alignment.from_org_domain ===
                headerAnalysis.domain_alignment.return_path_org_domain}
            <CheckCard
                id="domain-alignment"
                title="Domain Alignment"
                tag="DMARC"
                status={alignmentLevel !== "none" ? "pass" : "fail"}
                summary={alignmentSummary}
                docs={[docs.dmarcAlignment]}
            >
                <div class="card-body">
                    <p class="card-text small text-muted">
                        Domain alignment ensures that the visible "From" domain matches the domain
                        used for authentication (Return-Path or DKIM signature). Proper alignment is
                        crucial for DMARC compliance, regardless of the policy. It helps prevent
                        email spoofing by verifying that the sender domain is consistent across all
                        authentication layers. Only one of the following lines needs to pass.
                    </p>
                    {#each alignmentIssues as issue, i (i)}
                        <IssueAlert
                            title={issueLabel(issue.type)}
                            severity={issue.severity}
                            message={issue.message}
                            location={issue.location}
                            advice={issue.advice}
                            docs={issueDocLinks(issue.type)}
                        />
                    {/each}
                </div>
                <div class="list-group list-group-flush">
                    <div class="list-group-item d-flex ps-0">
                        <div
                            class="d-flex align-items-center justify-content-center"
                            style="writing-mode: vertical-rl; transform: rotate(180deg); font-size: 1.5rem; font-weight: bold; min-width: 3rem;"
                        >
                            SPF
                        </div>
                        <div class="flex-fill">
                            <div class="row flex-grow-1">
                                <div class="col-md-3">
                                    <small class="text-muted">Strict Alignment</small>
                                    <div>
                                        <span
                                            class="badge"
                                            class:bg-success={spfStrictAligned}
                                            class:bg-danger={!spfStrictAligned}
                                        >
                                            <i
                                                class="bi {spfStrictAligned
                                                    ? 'bi-check-circle-fill'
                                                    : 'bi-x-circle-fill'} me-1"
                                            ></i>
                                            <strong>{spfStrictAligned ? "Pass" : "Fail"}</strong>
                                        </span>
                                    </div>
                                    <div class="small text-muted mt-1">Exact domain match</div>
                                </div>
                                <div class="col-md-3">
                                    <small class="text-muted">Relaxed Alignment</small>
                                    <div>
                                        <span
                                            class="badge"
                                            class:bg-success={spfRelaxedAligned}
                                            class:bg-danger={!spfRelaxedAligned}
                                        >
                                            <i
                                                class="bi {spfRelaxedAligned
                                                    ? 'bi-check-circle-fill'
                                                    : 'bi-x-circle-fill'} me-1"
                                            ></i>
                                            <strong>{spfRelaxedAligned ? "Pass" : "Fail"}</strong>
                                        </span>
                                    </div>
                                    <div class="small text-muted mt-1">
                                        Organizational domain match
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <small class="text-muted">From Domain</small>
                                    <div>
                                        <code>
                                            {headerAnalysis.domain_alignment.from_domain || "-"}
                                        </code>
                                    </div>
                                    {#if headerAnalysis.domain_alignment.from_org_domain && headerAnalysis.domain_alignment.from_org_domain !== headerAnalysis.domain_alignment.from_domain}
                                        <div class="small text-muted mt-1">
                                            Org:
                                            <code>
                                                {headerAnalysis.domain_alignment.from_org_domain}
                                            </code>
                                        </div>
                                    {/if}
                                </div>
                                <div class="col-md-3">
                                    <small class="text-muted">Return-Path Domain</small>
                                    <div>
                                        <code>
                                            {headerAnalysis.domain_alignment.return_path_domain ||
                                                "-"}
                                        </code>
                                    </div>
                                    {#if headerAnalysis.domain_alignment.return_path_org_domain && headerAnalysis.domain_alignment.return_path_org_domain !== headerAnalysis.domain_alignment.return_path_domain}
                                        <div class="small text-muted mt-1">
                                            Org:
                                            <code>
                                                {headerAnalysis.domain_alignment
                                                    .return_path_org_domain}
                                            </code>
                                        </div>
                                    {/if}
                                </div>
                            </div>

                            <!-- Alignment Information based on DMARC policy -->
                            {#if dmarcRecord && headerAnalysis.domain_alignment.return_path_domain && headerAnalysis.domain_alignment.return_path_domain !== headerAnalysis.domain_alignment.from_domain}
                                <div
                                    class="alert mt-2 mb-0 small py-2 {dmarcRecord.spf_alignment ===
                                    'strict'
                                        ? 'alert-warning'
                                        : 'alert-info'}"
                                >
                                    {#if dmarcRecord.spf_alignment === "strict"}
                                        <i class="bi bi-exclamation-triangle me-1"></i>
                                        <strong>Strict SPF alignment required</strong> — Your DMARC policy
                                        requires exact domain match. The Return-Path domain must exactly
                                        match the From domain for SPF to pass DMARC alignment.
                                    {:else}
                                        <i class="bi bi-info-circle me-1"></i>
                                        <strong>Relaxed SPF alignment allowed</strong> — Your DMARC policy
                                        allows organizational domain matching. As long as both domains
                                        share the same organizational domain (e.g., mail.example.com and
                                        example.com), SPF alignment can pass.
                                    {/if}
                                </div>
                            {/if}
                        </div>
                    </div>

                    {#each headerAnalysis.domain_alignment.dkim_domains as dkim_domain, i (i)}
                        {@const dkim_aligned =
                            dkim_domain.domain === headerAnalysis.domain_alignment.from_domain}
                        {@const dkim_relaxed_aligned =
                            dkim_domain.org_domain ===
                            headerAnalysis.domain_alignment.from_org_domain}
                        <div class="list-group-item d-flex ps-0">
                            <div
                                class="d-flex align-items-center justify-content-center"
                                style="writing-mode: vertical-rl; transform: rotate(180deg); font-size: 1.5rem; font-weight: bold; min-width: 3rem;"
                            >
                                DKIM
                            </div>
                            <div class="flex-fill">
                                <div class="flex-fill">
                                    <div class="row flex-grow-1">
                                        <div class="col-md-3">
                                            <small class="text-muted">Strict Alignment</small>
                                            <div>
                                                <span
                                                    class="badge"
                                                    class:bg-success={dkim_aligned}
                                                    class:bg-danger={!dkim_aligned}
                                                >
                                                    <i
                                                        class="bi {dkim_aligned
                                                            ? 'bi-check-circle-fill'
                                                            : 'bi-x-circle-fill'} me-1"
                                                    ></i>
                                                    <strong>{dkim_aligned ? "Pass" : "Fail"}</strong
                                                    >
                                                </span>
                                            </div>
                                            <div class="small text-muted mt-1">
                                                Exact domain match
                                            </div>
                                        </div>
                                        <div class="col-md-3">
                                            <small class="text-muted">Relaxed Alignment</small>
                                            <div>
                                                <span
                                                    class="badge"
                                                    class:bg-success={dkim_relaxed_aligned}
                                                    class:bg-danger={!dkim_relaxed_aligned}
                                                >
                                                    <i
                                                        class="bi {dkim_relaxed_aligned
                                                            ? 'bi-check-circle-fill'
                                                            : 'bi-x-circle-fill'} me-1"
                                                    ></i>
                                                    <strong
                                                        >{dkim_relaxed_aligned
                                                            ? "Pass"
                                                            : "Fail"}</strong
                                                    >
                                                </span>
                                            </div>
                                            <div class="small text-muted mt-1">
                                                Organizational domain match
                                            </div>
                                        </div>
                                        <div class="col-md-3">
                                            <small class="text-muted">From Domain</small>
                                            <div>
                                                <code
                                                    >{headerAnalysis.domain_alignment.from_domain ||
                                                        "-"}</code
                                                >
                                            </div>
                                            {#if headerAnalysis.domain_alignment.from_org_domain && headerAnalysis.domain_alignment.from_org_domain !== headerAnalysis.domain_alignment.from_domain}
                                                <div class="small text-muted mt-1">
                                                    Org: <code
                                                        >{headerAnalysis.domain_alignment
                                                            .from_org_domain}</code
                                                    >
                                                </div>
                                            {/if}
                                        </div>
                                        <div class="col-md-3">
                                            <small class="text-muted">Signature Domain</small>
                                            <div><code>{dkim_domain.domain || "-"}</code></div>
                                            {#if dkim_domain.domain !== dkim_domain.org_domain}
                                                <div class="small text-muted mt-1">
                                                    Org: <code>{dkim_domain.org_domain}</code>
                                                </div>
                                            {/if}
                                        </div>
                                    </div>

                                    <!-- Alignment Information based on DMARC policy -->
                                    {#if dmarcRecord && dkim_domain.domain !== headerAnalysis.domain_alignment.from_domain}
                                        {#if dkim_domain.org_domain === headerAnalysis.domain_alignment.from_org_domain}
                                            <div
                                                class="alert mt-2 mb-0 small py-2 {dmarcRecord.dkim_alignment ===
                                                'strict'
                                                    ? 'alert-warning'
                                                    : 'alert-info'}"
                                            >
                                                {#if dmarcRecord.dkim_alignment === "strict"}
                                                    <i class="bi bi-exclamation-triangle me-1"></i>
                                                    <strong>Strict DKIM alignment required</strong> —
                                                    Your DMARC policy requires exact domain match. The
                                                    DKIM signature domain must exactly match the From
                                                    domain for DKIM to pass DMARC alignment.
                                                {:else}
                                                    <i class="bi bi-info-circle me-1"></i>
                                                    <strong>Relaxed DKIM alignment allowed</strong> —
                                                    Your DMARC policy allows organizational domain matching.
                                                    As long as both domains share the same organizational
                                                    domain (e.g., mail.example.com and example.com), DKIM
                                                    alignment can pass.
                                                {/if}
                                            </div>
                                        {/if}
                                    {/if}
                                </div>
                            </div>
                        </div>
                    {/each}
                </div>
            </CheckCard>
        {/if}

        {#if headerRows.length > 0}
            <div class="mt-3">
                <h5>Headers</h5>
                {#if problemRows.length > 0}
                    {@render headerTable(problemRows, true)}
                {:else}
                    <p class="text-muted small mb-2">
                        <i class="bi bi-check-circle-fill text-success me-1"></i>
                        Every required and recommended header is present and well-formed.
                    </p>
                {/if}
                {#if fineRows.length > 0}
                    <details class="passed-items">
                        <summary>
                            {fineRows.length} other header{fineRows.length > 1 ? "s" : ""} checked
                        </summary>
                        <div class="mt-2">
                            {@render headerTable(fineRows, false)}
                        </div>
                    </details>
                {/if}
            </div>
        {/if}
    </div>
    <div class="card-footer">
        <DocLinks
            label="Standards:"
            docs={[
                docs.messageFormat,
                docs.mimeVersion,
                docs.listUnsubscribe,
                docs.oneClickUnsubscribe,
            ]}
        />
    </div>
</ReportSection>

{#snippet headerTable(rows: [string, HeaderCheck][], withDocs: boolean)}
    <div class="table-responsive">
        <table class="table table-sm mb-2">
            <thead>
                <tr>
                    <th></th>
                    <th>When?</th>
                    <th>Present</th>
                    <th>Valid</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
                {#each rows as [name, check] (name)}
                    <tr>
                        <td>
                            <code>{name}</code>
                        </td>
                        <td>
                            {#if check.importance}
                                <small
                                    class="text-{check.importance === 'required'
                                        ? 'danger'
                                        : check.importance === 'recommended'
                                          ? 'warning'
                                          : 'secondary'}"
                                >
                                    {check.importance}
                                </small>
                            {/if}
                        </td>
                        <td>
                            <i
                                class="bi {check.present
                                    ? 'bi-check-circle text-success'
                                    : 'bi-x-circle text-danger'}"
                            ></i>
                        </td>
                        <td>
                            {#if check.present && check.valid !== undefined}
                                <i
                                    class="bi {check.valid
                                        ? 'bi-check-circle text-success'
                                        : 'bi-x-circle text-warning'}"
                                ></i>
                            {:else}
                                -
                            {/if}
                        </td>
                        <td>
                            <small class="text-muted text-truncate" title={check.value}
                                >{check.value || "-"}</small
                            >
                            {#each issuesAt.get(name) ?? [] as { issue, index } (index)}
                                <div class="small">
                                    <a class="link-warning" href="#{headerIssueAnchor(index)}">
                                        <i class="bi bi-exclamation-triangle me-1"></i>
                                        {issueLabel(issue.type)}
                                    </a>
                                </div>
                            {/each}
                            {#if withDocs}
                                <DocLinks docs={headerDocLinks(name)} label="" class="mt-1" />
                            {/if}
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/snippet}
