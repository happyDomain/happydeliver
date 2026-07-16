<script lang="ts">
    import type { SchemasAttachmentAnalysis } from "$lib/api/types.gen";
    import { getScoreColorClass } from "$lib/score";
    import { theme } from "$lib/stores/theme";
    import GradeDisplay from "./GradeDisplay.svelte";

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
            case "infected":
            case "malicious":
                return "bg-danger";
            case "suspicious":
                return "bg-warning";
            case "pending":
                return "bg-info";
            default:
                // unknown, skipped, error, too_large
                return "bg-secondary";
        }
    }
</script>

<div class="card shadow-sm" id="attachment-details">
    <div class="card-header {$theme === 'light' ? 'bg-white' : 'bg-dark'}">
        <h4 class="mb-0 d-flex justify-content-between align-items-center">
            <span>
                <i class="bi bi-paperclip me-2"></i>
                Attachment Analysis
            </span>
            <span>
                {#if attachmentsScore !== undefined}
                    <span class="badge bg-{getScoreColorClass(attachmentsScore)}">
                        {attachmentsScore}%
                    </span>
                {/if}
                {#if attachmentsGrade !== undefined}
                    <GradeDisplay grade={attachmentsGrade} size="small" />
                {/if}
            </span>
        </h4>
    </div>
    <div class="card-body">
        {#if !attachmentAnalysis.has_attachments}
            <p class="text-muted mb-0">
                <i class="bi bi-check-circle text-success me-2"></i>
                This email contains no attachments.
            </p>
        {:else}
            {#if attachmentAnalysis.clamav_enabled === false || attachmentAnalysis.virustotal_enabled === false}
                <div class="alert alert-secondary py-2 px-3 mb-3">
                    <i class="bi bi-info-circle me-1"></i>
                    {#if attachmentAnalysis.clamav_enabled === false && attachmentAnalysis.virustotal_enabled === false}
                        No antivirus scanner is configured on this server; only static checks
                        were performed.
                    {:else if attachmentAnalysis.clamav_enabled === false}
                        ClamAV scanning is not configured on this server.
                    {:else}
                        VirusTotal lookups are not configured on this server.
                    {/if}
                </div>
            {/if}

            {#each attachmentAnalysis.attachments || [] as attachment}
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
                                {#if attachment.virustotal?.permalink}
                                    <a
                                        href={attachment.virustotal.permalink}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        class="font-monospace text-break ms-1"
                                    >
                                        {attachment.sha256}
                                    </a>
                                {:else}
                                    <span class="font-monospace text-break ms-1">
                                        {attachment.sha256}
                                    </span>
                                {/if}
                            </div>
                        </div>
                    </div>

                    <div class="mt-2">
                        {#if attachment.clamav}
                            <span class="me-2">
                                <strong class="small">ClamAV:</strong>
                                <span class="badge {scannerBadgeClass(attachment.clamav.status)}">
                                    {attachment.clamav.status}
                                    {#if attachment.clamav.signature}
                                        — {attachment.clamav.signature}
                                    {/if}
                                </span>
                            </span>
                        {/if}
                        {#if attachment.virustotal}
                            <span>
                                <strong class="small">VirusTotal:</strong>
                                <span
                                    class="badge {scannerBadgeClass(attachment.virustotal.status)}"
                                >
                                    {attachment.virustotal.status}
                                    {#if attachment.virustotal.positives !== undefined && attachment.virustotal.total !== undefined}
                                        ({attachment.virustotal.positives}/{attachment.virustotal
                                            .total})
                                    {/if}
                                </span>
                            </span>
                        {/if}
                    </div>

                    {#if attachment.issues && attachment.issues.length > 0}
                        <div class="mt-3">
                            {#each attachment.issues as issue}
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
                                                <div class="small text-muted">
                                                    {issue.location}
                                                </div>
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
                </div>
            {/each}
        {/if}
    </div>
</div>
