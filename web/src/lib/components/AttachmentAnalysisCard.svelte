<script lang="ts">
    import type { SchemasAttachmentAnalysis, SchemasScanResult } from "$lib/api/types.gen";
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

    function scannerBadgeClass(status: string): string {
        switch (status) {
            case "clean":
                return "bg-success";
            case "malicious":
                return "bg-danger";
            case "pending":
                return "bg-info";
            default:
                // skipped, error
                return "bg-secondary";
        }
    }

    /**
     * Name of a scanner as a sentence calls it. A scanner nobody wrote a label for is shown
     * under the name it answers with: the report is meant to carry engines this build has
     * never heard of.
     */
    const scannerLabels: Record<string, string> = {
        clamav: "ClamAV",
    };

    function scannerLabel(scanner: string): string {
        return scannerLabels[scanner] ?? scanner;
    }

    /**
     * What a scanner says beyond its status: the name it gave what it recognised.
     */
    function scanEvidence(scan: SchemasScanResult): string {
        return scan.verdict ? ` — ${scan.verdict}` : "";
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
    {#if !attachmentAnalysis.has_attachments}
        <div class="card-body">
            <p class="text-muted mb-0">
                <i class="bi bi-check-circle text-success me-2"></i>
                This email contains no attachments.
            </p>
        </div>
    {:else}
        <div class="list-group list-group-flush">
            {#each attachmentAnalysis.attachments || [] as attachment, index (attachment.sha256 + index)}
                <div class="list-group-item">
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

                    <div class="mt-2">
                        <!-- Every scanner the report carries is shown, whatever it answered:
                             what a reader must be able to tell apart is a file nobody looked
                             at and one nothing was found in. A scanner the instance does not
                             run is simply not in the report. -->
                        {#each attachment.scans || [] as scan (scan.scanner)}
                            <span class="me-2">
                                <strong class="small">{scannerLabel(scan.scanner)}:</strong>
                                <span
                                    class="badge {scannerBadgeClass(scan.status)}"
                                    title={scan.detail ?? ""}
                                >
                                    {scan.status}{scanEvidence(scan)}
                                </span>
                            </span>
                        {/each}
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
        </div>
    {/if}
</div>
