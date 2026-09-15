<script lang="ts">
    import type { SchemasAttachmentAnalysis } from "$lib/api/types.gen";
    import { categoryLabel, groupIssuesByCategory, issueLabel, issueObserver } from "$lib/issues";
    import { getScoreColorClass } from "$lib/score";
    import { theme } from "$lib/stores/theme";
    import GradeDisplay from "./GradeDisplay.svelte";
    import IssueAlert from "./IssueAlert.svelte";

    interface Props {
        attachmentAnalysis: SchemasAttachmentAnalysis;
        attachmentsGrade?: string;
        attachmentsScore?: number;
    }

    let { attachmentAnalysis, attachmentsGrade, attachmentsScore }: Props = $props();

    function formatSize(size: number): string {
        if (size < 1024) return `${size} B`;
        if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
        return `${(size / (1024 * 1024)).toFixed(1)} MB`;
    }
</script>

<div class="card shadow-sm" id="attachment-details">
    <div class="card-header {$theme === 'light' ? 'bg-white' : 'bg-dark'}">
        <h4 class="mb-0 d-flex justify-content-between align-items-center">
            <span>
                <i class="bi bi-paperclip me-2"></i>
                Attachment Analysis
            </span>
            {#if attachmentsGrade}
                <span>
                    {#if attachmentsScore !== undefined}
                        <span class="badge bg-{getScoreColorClass(attachmentsScore)}">
                            {attachmentsScore}%
                        </span>
                    {/if}
                    <GradeDisplay grade={attachmentsGrade} size="small" />
                </span>
            {/if}
        </h4>
    </div>
    <div class="card-body">
        {#if !attachmentAnalysis.has_attachments}
            <p class="text-muted mb-0">
                <i class="bi bi-check-circle text-success me-2"></i>
                This email contains no attachments.
            </p>
        {:else}
            {#each attachmentAnalysis.attachments || [] as attachment, index (attachment.sha256 + index)}
                <div class="border rounded p-3 mb-3">
                    <div class="d-flex justify-content-between align-items-start flex-wrap">
                        <h5 class="mb-1">
                            <i class="bi bi-file-earmark me-1"></i>
                            {attachment.filename || "(unnamed attachment)"}
                            {#if attachment.inline}
                                <span class="badge bg-light text-dark border ms-1">inline</span>
                            {/if}
                        </h5>
                        <span class="text-muted small">{formatSize(attachment.size)}</span>
                    </div>

                    <div class="row mt-2">
                        <div class="col-md-6">
                            {#if attachment.declared_content_type}
                                <div class="small">
                                    <strong>Declared type:</strong>
                                    <span class="ms-1">{attachment.declared_content_type}</span>
                                </div>
                            {/if}
                            {#if attachment.detected_content_type}
                                <div class="small">
                                    <strong>Detected type:</strong>
                                    <span class="ms-1">{attachment.detected_content_type}</span>
                                </div>
                            {/if}
                        </div>
                        <div class="col-md-6">
                            <div class="small">
                                <strong>SHA-256:</strong>
                                <span class="font-monospace text-break ms-1">
                                    {attachment.sha256}
                                </span>
                            </div>
                        </div>
                    </div>

                    {#if attachment.issues && attachment.issues.length > 0}
                        <div class="mt-3">
                            {#each groupIssuesByCategory(attachment.issues) as group (group.category ?? "")}
                                <!-- A report from before the analysis recorded a reading has
                                     no heading to show: its findings are listed as they
                                     always were. -->
                                {#if group.category}
                                    <h6 class="text-muted text-uppercase small mt-3 mb-2">
                                        {categoryLabel(group.category)}
                                        <span class="badge bg-secondary ms-1">
                                            {group.issues.length}
                                        </span>
                                    </h6>
                                {/if}
                                {#each group.issues as placed (placed.index)}
                                    <IssueAlert
                                        title={issueLabel(placed.issue.type)}
                                        severity={placed.issue.severity}
                                        message={placed.issue.message}
                                        location={placed.issue.location}
                                        advice={placed.issue.advice}
                                        observer={issueObserver(placed.issue)}
                                        corroboratedBy={placed.issue.corroborated_by}
                                    />
                                {/each}
                            {/each}
                        </div>
                    {/if}
                </div>
            {/each}
        {/if}
    </div>
</div>
