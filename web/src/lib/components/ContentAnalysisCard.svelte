<script lang="ts">
    import type {
        ContentAnalysis,
        ContentIssues,
        ImageCheck,
        Issue,
        LinkCheck,
    } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import {
        compareBySeverity,
        contentAnchor,
        groupByChange,
        issueLabel,
        issueObserver,
        listed,
    } from "#lib/issues.js";
    import type { SectionStatus } from "#lib/sections.js";
    import CheckCard from "./CheckCard.svelte";
    import CheckList from "./CheckList.svelte";
    import IssueNote from "./IssueNote.svelte";
    import ReportSection from "./ReportSection.svelte";

    interface Props {
        contentAnalysis: ContentAnalysis;
        contentGrade?: string;
        contentScore?: number;
        status?: SectionStatus;
        open?: boolean;
    }

    let { contentAnalysis, contentGrade, contentScore, status, open = true }: Props = $props();

    /**
     * The issues of a check, or nothing when it has none: its own status then says how it
     * came out, as for a check with nothing graded.
     */
    function at(check: keyof ContentIssues): Issue[] | undefined {
        return listed(contentAnalysis.issues?.[check]);
    }

    // A report from before the issues were listed by check has them in one run, each kind
    // of defect once, saying how many times it was found.
    const legacy = $derived(
        groupByChange([...(contentAnalysis.html_issues ?? [])].sort(compareBySeverity)),
    );

    const hasHtml = $derived(contentAnalysis.has_html ?? false);
    const hasText = $derived(contentAnalysis.has_plaintext ?? false);

    // A row with something to say about it comes first, unfolded; the others are listed on
    // demand, under it.
    const reported = (row: { issues?: Issue[] }) => (row.issues?.length ?? 0) > 0;

    const links = $derived(contentAnalysis.links ?? []);
    const linkProblems = $derived(
        links.filter((l) => reported(l) || (l.status !== "valid" && l.status !== "redirected")),
    );
    const fineLinks = $derived(links.filter((l) => !linkProblems.includes(l)));

    const images = $derived(contentAnalysis.images ?? []);
    const imageProblems = $derived(
        images.filter((i) => reported(i) || i.is_broken || (!i.has_alt && !i.is_tracking_pixel)),
    );
    const fineImages = $derived(images.filter((i) => !imageProblems.includes(i)));
    const withoutAlt = $derived(images.filter((i) => !i.has_alt && !i.is_tracking_pixel).length);

    const methods = $derived(contentAnalysis.unsubscribe_methods ?? []);
    const methodLabels: Record<string, string> = {
        link: "Link in the body",
        mailto: "List-Unsubscribe by email",
        "list-unsubscribe-header": "List-Unsubscribe by URL",
        "one-click": "One-click (RFC 8058)",
    };

    const plural = (n: number, one: string, many: string) => `${n} ${n > 1 ? many : one}`;

    const structureSummary = $derived(
        hasHtml && hasText
            ? "HTML with a plain text alternative"
            : hasHtml
              ? "HTML only, no plain text alternative"
              : hasText
                ? "Plain text only"
                : "No readable part",
    );

    const linksSummary = $derived(
        linkProblems.length > 0
            ? `${linkProblems.length} of ${plural(links.length, "link", "links")} to check`
            : `${plural(links.length, "link", "links")}, all answering`,
    );

    const imagesSummary = $derived(
        [
            plural(images.length, "image", "images"),
            imageProblems.some((i) => i.is_broken) &&
                `${imageProblems.filter((i) => i.is_broken).length} not loading`,
            withoutAlt > 0 && `${withoutAlt} without alt text`,
        ]
            .filter(Boolean)
            .join(", "),
    );

    // The tone of a row is that of its gravest issue, as the icon of a check is.
    function tone(issues?: Issue[]): "danger" | "warning" | "info" | undefined {
        const gravest = [...(issues ?? [])].sort(compareBySeverity)[0];
        if (!gravest) return undefined;
        if (gravest.severity === "critical" || gravest.severity === "high") return "danger";
        return gravest.severity === "info" ? "info" : "warning";
    }
</script>

<ReportSection
    id="content-details"
    title="Content Analysis"
    icon="file-text"
    grade={contentGrade}
    score={contentScore}
    {status}
    {open}
>
    <div class="card-body">
        <!-- A report from before the issues were listed by check has them here, in one run. -->
        {#each legacy as alike, i (i)}
            <IssueNote
                issue={alike[0]}
                detail={alike.length > 1 ? `Found ${alike.length} times.` : undefined}
                penalty={alike.reduce((sum, issue) => sum + (issue.penalty ?? 0), 0)}
            />
        {/each}

        <CheckList title="Message body">
            <CheckCard
                id={contentAnchor("structure")}
                title="Structure"
                tag="MIME"
                status="pass"
                summary={structureSummary}
                issues={at("structure")}
            >
                <div class="card-body">
                    <dl class="check-facts">
                        <dt>HTML part</dt>
                        <dd>{@render presence(hasHtml)}</dd>
                        <dt>Plain text part</dt>
                        <dd>{@render presence(hasText)}</dd>
                    </dl>
                    <p class="check-about">
                        A plain text alternative is what clients and readers preferring text
                        display, and what filters compare the HTML with.
                    </p>
                </div>
            </CheckCard>

            {#if (hasHtml && hasText) || at("text_alternative")}
                <CheckCard
                    id={contentAnchor("text_alternative")}
                    title="Text alternative"
                    status="pass"
                    summary="Says what the HTML says"
                    issues={at("text_alternative")}
                >
                    <div class="card-body">
                        <p class="check-about">
                            The plain text part should carry the same message and lead to the same
                            places as the HTML part, which is how it reads when generated from it.
                        </p>
                    </div>
                </CheckCard>
            {/if}

            {#if links.length > 0 || at("links")}
                <CheckCard
                    id={contentAnchor("links")}
                    title="Links"
                    status="pass"
                    summary={links.length > 0 ? linksSummary : undefined}
                    issues={at("links")}
                    rows={{
                        issues: links.flatMap((link) => link.issues ?? []),
                        one: "link",
                        many: "links",
                    }}
                >
                    <div class="card-body">
                        {#if linkProblems.length > 0}
                            {@render linkTable(linkProblems)}
                        {/if}
                        {#if fineLinks.length > 0}
                            <details class="passed-items mb-2" open={linkProblems.length === 0}>
                                <summary>
                                    {plural(fineLinks.length, "link", "links")} answering
                                </summary>
                                <div class="mt-2">{@render linkTable(fineLinks)}</div>
                            </details>
                        {/if}
                        <p class="check-about">
                            Every link is followed to where it ends: one that does not answer, or
                            only after a long detour, is what the recipient gets on clicking.
                        </p>
                    </div>
                </CheckCard>
            {/if}

            {#if images.length > 0 || at("images")}
                <CheckCard
                    id={contentAnchor("images")}
                    title="Images"
                    status="pass"
                    summary={images.length > 0 ? imagesSummary : undefined}
                    issues={at("images")}
                    rows={{
                        issues: images.flatMap((image) => image.issues ?? []),
                        one: "image",
                        many: "images",
                    }}
                >
                    <div class="card-body">
                        {#if contentAnalysis.text_to_image_ratio !== undefined}
                            <dl class="check-facts">
                                <dt>Text per image</dt>
                                <dd>
                                    {Math.round(contentAnalysis.text_to_image_ratio)} characters
                                </dd>
                            </dl>
                        {/if}
                        {#if imageProblems.length > 0}
                            {@render imageTable(imageProblems)}
                        {/if}
                        {#if fineImages.length > 0}
                            <details class="passed-items mb-2" open={imageProblems.length === 0}>
                                <summary>
                                    {plural(fineImages.length, "image", "images")} loading, with alt text
                                </summary>
                                <div class="mt-2">{@render imageTable(fineImages)}</div>
                            </details>
                        {/if}
                        <p class="check-about">
                            Many clients block images until asked: the alt text is what the
                            recipient reads in their place, and the text around them what a filter
                            reads of the message.
                        </p>
                    </div>
                </CheckCard>
            {/if}

            <CheckCard
                id={contentAnchor("unsubscribe")}
                title="Unsubscribe"
                status={methods.length > 0 ? "pass" : "neutral"}
                summary={methods.length > 0
                    ? methods.map((m) => methodLabels[m] ?? m).join(", ")
                    : "No way to unsubscribe found"}
                docs={[docs.listUnsubscribe, docs.oneClickUnsubscribe]}
                issues={at("unsubscribe")}
            >
                <div class="card-body">
                    <p class="check-about">
                        Bulk senders must let recipients unsubscribe in one click: one who cannot
                        find how reports the message as spam instead. A personal or transactional
                        message needs none.
                    </p>
                </div>
            </CheckCard>

            {#if hasHtml || at("rendering")}
                <CheckCard
                    id={contentAnchor("rendering")}
                    title="Rendering"
                    status="pass"
                    summary="Renders alike in the common clients, text readable"
                    docs={[docs.canIEmail]}
                    issues={at("rendering")}
                >
                    <div class="card-body">
                        <p class="check-about">
                            What the common email clients drop of the HTML and CSS, as Can I email
                            records it, and text too close in colour to its background to be read.
                        </p>
                    </div>
                </CheckCard>
            {/if}

            {#if hasHtml || at("markup")}
                <CheckCard
                    id={contentAnchor("markup")}
                    title="Markup"
                    status="pass"
                    summary="No blocked markup nor hidden text"
                    issues={at("markup")}
                >
                    <div class="card-body">
                        <p class="check-about">
                            Scripts, forms and embedded frames are removed by every client, and text
                            hidden from the reader is what filters look for in spam.
                        </p>
                    </div>
                </CheckCard>
            {/if}

            {#if at("attachments")}
                <CheckCard
                    id={contentAnchor("attachments")}
                    title="Attachments"
                    status="pass"
                    issues={at("attachments")}
                >
                    <div class="card-body">
                        <p class="check-about">What the spam filter saw in the attached files.</p>
                    </div>
                </CheckCard>
            {/if}
        </CheckList>
    </div>
</ReportSection>

{#snippet presence(present: boolean)}
    <i
        class="bi me-1 {present ? 'bi-check-circle-fill text-success' : 'bi-x-circle text-muted'}"
        aria-hidden="true"
    ></i>{present ? "Present" : "Absent"}
{/snippet}

<!-- What the row is reported for, below what it is: the advice is on the check above, once
     for every row it applies to. -->
{#snippet rowIssues(issues?: Issue[])}
    {#each [...(issues ?? [])].sort(compareBySeverity) as issue, i (i)}
        {@const observer = issueObserver(issue)}
        <div class="small text-{tone([issue])}-emphasis">
            <span class="fw-semibold">{issueLabel(issue.type)}:</span>
            {issue.message}
            {#if observer}<span class="text-body-secondary">({observer})</span>{/if}
        </div>
    {/each}
{/snippet}

{#snippet linkTable(rows: LinkCheck[])}
    <div class="table-responsive">
        <table class="table table-sm align-middle content-rows mb-2">
            <thead>
                <tr>
                    <th>URL</th>
                    <th class="text-end">HTTP</th>
                </tr>
            </thead>
            <tbody>
                {#each rows as link, i (i)}
                    <tr class={tone(link.issues) ?? (link.status === "broken" ? "danger" : "")}>
                        <td>
                            <code class="text-break">{link.url}</code>
                            {#if link.is_shortened}
                                <span class="badge text-bg-warning ms-1">Shortened</span>
                            {/if}
                            {#if link.final_url && link.final_url !== link.url}
                                <div
                                    class="small text-body-secondary text-break"
                                    title={link.redirect_chain?.join(" → ")}
                                >
                                    → {link.final_url}
                                    ({plural(link.redirect_chain?.length ?? 0, "hop", "hops")})
                                </div>
                            {/if}
                            {@render rowIssues(link.issues)}
                        </td>
                        <td class="text-end text-nowrap">
                            {#if link.http_code}
                                {link.http_code}
                            {:else}
                                <span class="text-body-secondary">{link.status}</span>
                            {/if}
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/snippet}

{#snippet imageTable(rows: ImageCheck[])}
    <div class="table-responsive">
        <table class="table table-sm align-middle content-rows mb-2">
            <thead>
                <tr>
                    <th>Source</th>
                    <th>Alt text</th>
                </tr>
            </thead>
            <tbody>
                {#each rows as image, i (i)}
                    <tr
                        class={tone(image.issues) ??
                            (image.is_broken
                                ? "danger"
                                : !image.has_alt && !image.is_tracking_pixel
                                  ? "warning"
                                  : "")}
                    >
                        <td>
                            <code class="text-break">{image.src || "-"}</code>
                            {#if image.is_tracking_pixel}
                                <span class="badge text-bg-secondary ms-1">Tracking pixel</span>
                            {/if}
                            {#if image.is_broken}
                                <div class="small text-danger-emphasis">
                                    <span class="fw-semibold">Does not load</span>{image.http_code
                                        ? ` (HTTP ${image.http_code})`
                                        : ""}
                                </div>
                            {/if}
                            {@render rowIssues(image.issues)}
                        </td>
                        <td>
                            {#if image.has_alt}
                                <small>{image.alt_text || "Empty, as for a decoration"}</small>
                            {:else if image.is_tracking_pixel}
                                <small class="text-body-secondary">Not needed</small>
                            {:else}
                                <small class="text-warning-emphasis">Missing</small>
                            {/if}
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/snippet}

<style>
    /* A reported row is tinted by the gravity of what it is reported for, as a header line
       of the header section is. */
    .content-rows tr {
        --tone: transparent;

        > td {
            background: color-mix(in srgb, var(--tone) 10%, var(--bs-table-bg));
        }

        &.warning {
            --tone: var(--bs-warning);
        }

        &.danger {
            --tone: var(--bs-danger);
        }

        &.info {
            --tone: var(--bs-info);
        }
    }
</style>
