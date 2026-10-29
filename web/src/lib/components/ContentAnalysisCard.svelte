<script lang="ts">
    import type { ContentAnalysis, ImageCheck, LinkCheck } from "#lib/api/types.gen.js";
    import { issueDocLinks } from "#lib/docs.js";
    import type { SectionStatus } from "#lib/sections.js";
    import {
        categoryLabel,
        contentIssueAnchor,
        issueLabel,
        groupIssuesByCategory,
        issueObserver,
    } from "#lib/issues.js";
    import IssueAlert from "./IssueAlert.svelte";
    import ReportSection from "./ReportSection.svelte";

    interface Props {
        contentAnalysis: ContentAnalysis;
        contentGrade?: string;
        contentScore?: number;
        status?: SectionStatus;
        open?: boolean;
    }

    let { contentAnalysis, contentGrade, contentScore, status, open = true }: Props = $props();

    // A link that answered, directly or after redirections, and an image that loads with a
    // text alternative are the expected case: listed only on demand.
    const links = $derived(contentAnalysis.links ?? []);
    const problemLinks = $derived(
        links.filter((l) => l.status !== "valid" && l.status !== "redirected"),
    );
    const fineLinks = $derived(
        links.filter((l) => l.status === "valid" || l.status === "redirected"),
    );
    const images = $derived(contentAnalysis.images ?? []);
    const problemImages = $derived(images.filter((i) => i.is_broken || !i.has_alt));
    const fineImages = $derived(images.filter((i) => !i.is_broken && i.has_alt));

    // The findings are shown by the reading they answer rather than in one run: a sender
    // fixing what a filter reads and a developer fixing what a client renders are looking
    // for different things in the same list.
    const issueGroups = $derived(groupIssuesByCategory(contentAnalysis.html_issues));
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
        <ul class="d-flex flex-wrap row-gap-2 column-gap-4 list-unstyled mb-3">
            <li>
                <i
                    class="bi {contentAnalysis.has_html
                        ? 'bi-check-circle text-success'
                        : 'bi-x-circle text-muted'} me-1"
                ></i>
                HTML part
            </li>
            <li>
                <i
                    class="bi {contentAnalysis.has_plaintext
                        ? 'bi-check-circle text-success'
                        : 'bi-x-circle text-muted'} me-1"
                ></i>
                Plain text part
            </li>
            {#if typeof contentAnalysis.has_unsubscribe_link === "boolean"}
                <li>
                    <i
                        class="bi {contentAnalysis.has_unsubscribe_link
                            ? 'bi-check-circle text-success'
                            : 'bi-x-circle text-warning'} me-1"
                    ></i>
                    Unsubscribe link
                    {#each contentAnalysis.unsubscribe_methods ?? [] as method (method)}
                        <span class="badge bg-info ms-1">{method}</span>
                    {/each}
                </li>
            {/if}
            {#if contentAnalysis.text_to_image_ratio !== undefined}
                <li>
                    Text to image ratio:
                    <strong>{contentAnalysis.text_to_image_ratio.toFixed(2)}</strong>
                </li>
            {/if}
        </ul>

        {#if issueGroups.length > 0}
            <div class="mt-3">
                <h5>Content Issues</h5>
                {#each issueGroups as group (group.category ?? "")}
                    <!-- A report from before the analysis recorded a reading has no heading
                         to show: its findings are listed as they always were. -->
                    {#if group.category}
                        <h6 class="text-muted text-uppercase small mt-3 mb-2">
                            {categoryLabel(group.category)}
                            <span class="badge bg-secondary ms-1">{group.issues.length}</span>
                        </h6>
                    {/if}
                    {#each group.issues as placed (placed.index)}
                        <IssueAlert
                            id={contentIssueAnchor(placed.index)}
                            title={issueLabel(placed.issue.type)}
                            severity={placed.issue.severity}
                            message={placed.issue.message}
                            location={placed.issue.location}
                            advice={placed.issue.advice}
                            observer={issueObserver(placed.issue)}
                            symbol={placed.issue.symbol}
                            corroboratedBy={placed.issue.corroborated_by}
                            docs={issueDocLinks(placed.issue.type)}
                            penalty={placed.issue.penalty}
                        />
                    {/each}
                {/each}
            </div>
        {/if}

        {#if links.length > 0}
            <div class="mt-3">
                <h5>Links ({links.length})</h5>
                {#if problemLinks.length > 0}
                    {@render linkTable(problemLinks)}
                {:else}
                    <p class="text-muted small mb-2">
                        <i class="bi bi-check-circle-fill text-success me-1"></i>
                        Every link answered.
                    </p>
                {/if}
                {#if fineLinks.length > 0}
                    <details class="passed-items">
                        <summary>
                            {fineLinks.length} link{fineLinks.length > 1 ? "s" : ""} reachable
                        </summary>
                        <div class="mt-2">{@render linkTable(fineLinks)}</div>
                    </details>
                {/if}
            </div>
        {/if}

        {#if images.length > 0}
            <div class="mt-3">
                <h5>Images ({images.length})</h5>
                {#if problemImages.length > 0}
                    {@render imageTable(problemImages)}
                {:else}
                    <p class="text-muted small mb-2">
                        <i class="bi bi-check-circle-fill text-success me-1"></i>
                        Every image loads and has a text alternative.
                    </p>
                {/if}
                {#if fineImages.length > 0}
                    <details class="passed-items">
                        <summary>
                            {fineImages.length} image{fineImages.length > 1 ? "s" : ""} with alt text
                        </summary>
                        <div class="mt-2">{@render imageTable(fineImages)}</div>
                    </details>
                {/if}
            </div>
        {/if}
    </div>
</ReportSection>

{#snippet linkTable(rows: LinkCheck[])}
    <div class="table-responsive">
        <table class="table table-sm mb-2">
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Status</th>
                    <th>HTTP Code</th>
                </tr>
            </thead>
            <tbody>
                {#each rows as link, i (i)}
                    <tr>
                        <td>
                            <small class="text-break">{link.url}</small>
                            {#if link.is_shortened}
                                <span class="badge bg-warning ms-1">Shortened</span>
                            {/if}
                            {#if link.redirect_chain && link.redirect_chain.length > 0}
                                <div>
                                    <small
                                        class="text-muted text-break"
                                        title={link.redirect_chain.join(" → ")}
                                    >
                                        → {link.redirect_chain.length} redirect{link.redirect_chain
                                            .length > 1
                                            ? "s"
                                            : ""}, ending at {link.final_url ??
                                            link.redirect_chain[link.redirect_chain.length - 1]}
                                    </small>
                                </div>
                            {/if}
                        </td>
                        <td>
                            <span
                                class="badge {link.status === 'valid'
                                    ? 'bg-success'
                                    : link.status === 'broken'
                                      ? 'bg-danger'
                                      : link.status === 'redirected'
                                        ? 'bg-info'
                                        : 'bg-warning'}"
                            >
                                {link.status}
                            </span>
                        </td>
                        <td>{link.http_code || "-"}</td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/snippet}

{#snippet imageTable(rows: ImageCheck[])}
    <div class="table-responsive">
        <table class="table table-sm mb-2">
            <thead>
                <tr>
                    <th>Source</th>
                    <th>Alt Text</th>
                    <th>Tracking</th>
                </tr>
            </thead>
            <tbody>
                {#each rows as image, i (i)}
                    <tr>
                        <td>
                            <small class="text-break">{image.src || "-"}</small>
                            {#if image.is_broken}
                                <span class="badge bg-danger ms-1">
                                    Does not load{image.http_code
                                        ? ` (HTTP ${image.http_code})`
                                        : ""}
                                </span>
                            {/if}
                        </td>
                        <td>
                            {#if image.has_alt}
                                <i class="bi bi-check-circle text-success me-1"></i>
                                <small>{image.alt_text || "Present"}</small>
                            {:else}
                                <i class="bi bi-x-circle text-warning me-1"></i>
                                <small class="text-muted">Missing</small>
                            {/if}
                        </td>
                        <td>
                            {#if image.is_tracking_pixel}
                                <span class="badge bg-info">Tracking Pixel</span>
                            {:else}
                                -
                            {/if}
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/snippet}
