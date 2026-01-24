<script lang="ts">
    import type { ContentAnalysis } from "$lib/api/types.gen";
    import { getScoreColorClass } from "$lib/score";
    import { theme } from "$lib/stores/theme";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        contentAnalysis: ContentAnalysis;
        contentGrade?: string;
        contentScore?: number;
    }

    let { contentAnalysis, contentGrade, contentScore }: Props = $props();
</script>

<div class="card shadow-sm" id="content-details">
    <div class="card-header {$theme === 'light' ? 'bg-white' : 'bg-dark'}">
        <h4 class="mb-0 d-flex justify-content-between align-items-center">
            <span>
                <i class="bi bi-file-text me-2"></i>
                Content Analysis
            </span>
            <span>
                {#if contentScore !== undefined}
                    <span class="badge bg-{getScoreColorClass(contentScore)}">
                        {contentScore}%
                    </span>
                {/if}
                {#if contentGrade !== undefined}
                    <GradeDisplay grade={contentGrade} size="small" />
                {/if}
            </span>
        </h4>
    </div>
    <div class="card-body">
        <div class="row mb-3">
            <div class="col-md-6">
                <div class="d-flex align-items-center mb-2">
                    <i
                        class="bi {contentAnalysis.has_html
                            ? 'bi-check-circle text-success'
                            : 'bi-x-circle text-muted'} me-2"
                    ></i>
                    <span>HTML Part</span>
                </div>
                <div class="d-flex align-items-center mb-2">
                    <i
                        class="bi {contentAnalysis.has_plaintext
                            ? 'bi-check-circle text-success'
                            : 'bi-x-circle text-muted'} me-2"
                    ></i>
                    <span>Plaintext Part</span>
                </div>
                {#if typeof contentAnalysis.has_unsubscribe_link === "boolean"}
                    <div class="d-flex align-items-center mb-2">
                        <i
                            class="bi {contentAnalysis.has_unsubscribe_link
                                ? 'bi-check-circle text-success'
                                : 'bi-x-circle text-warning'} me-2"
                        ></i>
                        <span>Unsubscribe Link</span>
                    </div>
                {/if}
            </div>
            <div class="col-md-6">
                {#if contentAnalysis.text_to_image_ratio !== undefined}
                    <div class="mb-2">
                        <strong>Text to Image Ratio:</strong>
                        <span class="ms-2">{contentAnalysis.text_to_image_ratio.toFixed(2)}</span>
                    </div>
                {/if}
                {#if contentAnalysis.unsubscribe_methods && contentAnalysis.unsubscribe_methods.length > 0}
                    <div class="mb-2">
                        <strong>Unsubscribe Methods:</strong>
                        <div class="mt-1">
                            {#each contentAnalysis.unsubscribe_methods as method}
                                <span class="badge bg-info me-1">{method}</span>
                            {/each}
                        </div>
                    </div>
                {/if}
            </div>
        </div>

        {#if contentAnalysis.html_issues && contentAnalysis.html_issues.length > 0}
            <div class="mt-3">
                <h5>Content Issues</h5>
                {#each contentAnalysis.html_issues as issue}
                    <div
                        class="alert alert-{issue.severity === 'critical' ||
                        issue.severity === 'high'
                            ? 'danger'
                            : issue.severity === 'medium'
                              ? 'warning'
                              : 'info'} py-2 px-3 mb-2"
                    >
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <strong>{issue.type}</strong>
                                <div class="small">{issue.message}</div>
                                {#if issue.location}
                                    <div class="small text-muted">{issue.location}</div>
                                {/if}
                                {#if issue.advice}
                                    <div class="small mt-1">
                                        <i class="bi bi-lightbulb me-1"></i>
                                        {issue.advice}
                                    </div>
                                {/if}
                            </div>
                            <span class="badge bg-secondary">{issue.severity}</span>
                        </div>
                    </div>
                {/each}
            </div>
        {/if}

        {#if contentAnalysis.links && contentAnalysis.links.length > 0}
            <div class="mt-3">
                <h5>Links ({contentAnalysis.links.length})</h5>
                <div class="table-responsive">
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>Status</th>
                                <th>HTTP Code</th>
                            </tr>
                        </thead>
                        <tbody>
                            {#each contentAnalysis.links as link}
                                <tr>
                                    <td>
                                        <small class="text-break">{link.url}</small>
                                        {#if link.is_shortened}
                                            <span class="badge bg-warning ms-1">Shortened</span>
                                        {/if}
                                    </td>
                                    <td>
                                        <span
                                            class="badge {link.status === 'valid'
                                                ? 'bg-success'
                                                : link.status === 'broken'
                                                  ? 'bg-danger'
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
            </div>
        {/if}

        {#if contentAnalysis.images && contentAnalysis.images.length > 0}
            <div class="mt-3">
                <h5>Images ({contentAnalysis.images.length})</h5>
                <div class="table-responsive">
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>Source</th>
                                <th>Alt Text</th>
                                <th>Tracking</th>
                            </tr>
                        </thead>
                        <tbody>
                            {#each contentAnalysis.images as image}
                                <tr>
                                    <td><small class="text-break">{image.src || "-"}</small></td>
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
            </div>
        {/if}
    </div>
</div>
