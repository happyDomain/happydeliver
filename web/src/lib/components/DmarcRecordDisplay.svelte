<script lang="ts">
    import type { DMARCRecord } from "$lib/api/types.gen";

    interface Props {
        dmarcRecord?: DMARCRecord;
    }

    let { dmarcRecord }: Props = $props();

    // Helper function to determine policy strength
    const policyStrength = (policy: string | undefined): number => {
        const strength: Record<string, number> = { none: 0, quarantine: 1, reject: 2 };
        return strength[policy || "none"] || 0;
    };
</script>

{#if dmarcRecord}
    <div class="card mb-4">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="text-muted mb-0">
                <i
                    class="bi"
                    class:bi-check-circle-fill={dmarcRecord.valid && dmarcRecord.policy != "none"}
                    class:text-success={dmarcRecord.valid && dmarcRecord.policy != "none"}
                    class:bi-arrow-up-circle-fill={dmarcRecord.valid &&
                        dmarcRecord.policy == "none"}
                    class:text-warning={dmarcRecord.valid && dmarcRecord.policy == "none"}
                    class:bi-x-circle-fill={!dmarcRecord.valid}
                    class:text-danger={!dmarcRecord.valid}
                ></i>
                Domain-based Message Authentication
            </h5>
            <span class="badge bg-secondary">DMARC</span>
        </div>
        <div class="card-body">
            <p class="card-text small text-muted mb-2">
                DMARC builds on SPF and DKIM by telling receiving servers what to do with emails
                that fail authentication checks. It also enables reporting so you can monitor your
                email security.
            </p>

            <hr />

            <!-- Status -->
            <div class="mb-2">
                <strong>Status:</strong>
                {#if dmarcRecord.valid}
                    <span class="badge bg-success">Valid</span>
                {:else}
                    <span class="badge bg-danger">Invalid</span>
                {/if}
            </div>

            <!-- Policy -->
            {#if dmarcRecord.policy}
                <div class="mb-3">
                    <strong>Policy:</strong>
                    <span
                        class="badge {dmarcRecord.policy === 'reject'
                            ? 'bg-success'
                            : dmarcRecord.policy === 'quarantine'
                              ? 'bg-warning'
                              : 'bg-secondary'}"
                    >
                        {dmarcRecord.policy}
                    </span>
                    {#if dmarcRecord.policy === "reject"}
                        <div class="alert alert-success mt-2 mb-0 small">
                            <i class="bi bi-shield-check me-1"></i>
                            <strong>Maximum protection</strong> — emails failing DMARC checks are rejected.
                            This provides the strongest defense against spoofing and phishing.
                        </div>
                    {:else if dmarcRecord.policy === "quarantine"}
                        <div class="alert alert-info mt-2 mb-0 small">
                            <i class="bi bi-check-circle me-1"></i>
                            <strong>Good protection</strong> — emails failing DMARC checks are
                            quarantined (sent to spam). This is a safe middle ground.<br />
                            <i class="bi bi-arrow-up-circle me-1"></i>
                            Once you've validated your configuration and ensured all legitimate mail
                            passes, consider upgrading to <code>p=reject</code> for maximum protection.
                        </div>
                    {:else if dmarcRecord.policy === "none"}
                        <div class="alert alert-warning mt-2 mb-0 small">
                            <i class="bi bi-exclamation-triangle me-1"></i>
                            <strong>Monitoring only</strong> — emails failing DMARC are delivered
                            normally. This is only recommended during initial setup.<br />
                            <i class="bi bi-arrow-up-circle me-1"></i>
                            After monitoring reports, upgrade to <code>p=quarantine</code> or
                            <code>p=reject</code> to actively protect your domain.
                        </div>
                    {:else}
                        <div class="alert alert-danger mt-2 mb-0 small">
                            <i class="bi bi-x-circle me-1"></i>
                            <strong>Unknown policy</strong> — the policy value is not recognized. Valid
                            options are: none, quarantine, or reject.
                        </div>
                    {/if}
                </div>
            {/if}

            <!-- Subdomain Policy -->
            {#if dmarcRecord.subdomain_policy}
                {@const mainStrength = policyStrength(dmarcRecord.policy)}
                {@const subStrength = policyStrength(dmarcRecord.subdomain_policy)}
                <div class="mb-3">
                    <strong>Subdomain Policy:</strong>
                    <span
                        class="badge {dmarcRecord.subdomain_policy === 'reject'
                            ? 'bg-success'
                            : dmarcRecord.subdomain_policy === 'quarantine'
                              ? 'bg-warning'
                              : 'bg-secondary'}"
                    >
                        {dmarcRecord.subdomain_policy}
                    </span>
                    {#if subStrength >= mainStrength}
                        <div class="alert alert-success mt-2 mb-0 small">
                            <i class="bi bi-check-circle me-1"></i>
                            <strong>Good configuration</strong> — subdomain policy is equal to or stricter
                            than main policy.
                        </div>
                    {:else}
                        <div class="alert alert-warning mt-2 mb-0 small">
                            <i class="bi bi-exclamation-triangle me-1"></i>
                            <strong>Weaker subdomain protection</strong> — consider setting
                            <code>sp={dmarcRecord.policy}</code> to match your main policy for consistent
                            protection.
                        </div>
                    {/if}
                </div>
            {:else if dmarcRecord.policy}
                <div class="mb-3">
                    <strong>Subdomain Policy:</strong>
                    <span class="badge bg-info">Inherits main policy</span>
                    <div class="alert alert-success mt-2 mb-0 small">
                        <i class="bi bi-check-circle me-1"></i>
                        <strong>Good default</strong> — subdomains inherit the main policy (<code
                            >{dmarcRecord.policy}</code
                        >) which provides consistent protection.
                    </div>
                </div>
            {/if}

            <!-- Percentage -->
            {#if dmarcRecord.percentage !== undefined}
                <div class="mb-3">
                    <strong>Enforcement Percentage:</strong>
                    <span
                        class="badge {dmarcRecord.percentage === 100
                            ? 'bg-success'
                            : dmarcRecord.percentage >= 50
                              ? 'bg-warning'
                              : 'bg-danger'}"
                    >
                        {dmarcRecord.percentage}%
                    </span>
                    {#if dmarcRecord.percentage === 100}
                        <div class="alert alert-success mt-2 mb-0 small">
                            <i class="bi bi-check-circle me-1"></i>
                            <strong>Full enforcement</strong> — all messages are subject to DMARC policy.
                            This provides maximum protection.
                        </div>
                    {:else if dmarcRecord.percentage >= 50}
                        <div class="alert alert-warning mt-2 mb-0 small">
                            <i class="bi bi-exclamation-triangle me-1"></i>
                            <strong>Partial enforcement</strong> — only {dmarcRecord.percentage}% of
                            messages are subject to DMARC policy. Consider increasing to
                            <code>pct=100</code> once you've validated your configuration.
                        </div>
                    {:else}
                        <div class="alert alert-danger mt-2 mb-0 small">
                            <i class="bi bi-x-circle me-1"></i>
                            <strong>Low enforcement</strong> — only {dmarcRecord.percentage}% of
                            messages are protected. Gradually increase to <code>pct=100</code> for full
                            protection.
                        </div>
                    {/if}
                </div>
            {:else if dmarcRecord.policy}
                <div class="mb-3">
                    <strong>Enforcement Percentage:</strong>
                    <span class="badge bg-success">100% (default)</span>
                    <div class="alert alert-success mt-2 mb-0 small">
                        <i class="bi bi-check-circle me-1"></i>
                        <strong>Full enforcement</strong> — all messages are subject to DMARC policy
                        by default.
                    </div>
                </div>
            {/if}

            <!-- SPF Alignment -->
            {#if dmarcRecord.spf_alignment}
                <div class="mb-3">
                    <strong>SPF Alignment:</strong>
                    <span
                        class="badge {dmarcRecord.spf_alignment === 'strict'
                            ? 'bg-success'
                            : 'bg-info'}"
                    >
                        {dmarcRecord.spf_alignment}
                    </span>
                    {#if dmarcRecord.spf_alignment === "relaxed"}
                        <div class="alert alert-info mt-2 mb-0 small">
                            <i class="bi bi-check-circle me-1"></i>
                            <strong>Recommended for most senders</strong> — ensures legitimate
                            subdomain mail passes.<br />
                            <i class="bi bi-exclamation-triangle me-1"></i>
                            For maximum brand protection, consider strict alignment (<code
                                >aspf=s</code
                            >) once your sending domains are standardized.
                        </div>
                    {:else}
                        <div class="alert alert-success mt-2 mb-0 small">
                            <i class="bi bi-shield-check me-1"></i>
                            <strong>Maximum brand protection</strong> — only exact domain matches are
                            accepted. Ensure all legitimate mail comes from the exact From domain.
                        </div>
                    {/if}
                </div>
            {/if}

            <!-- DKIM Alignment -->
            {#if dmarcRecord.dkim_alignment}
                <div class="mb-3">
                    <strong>DKIM Alignment:</strong>
                    <span
                        class="badge {dmarcRecord.dkim_alignment === 'strict'
                            ? 'bg-success'
                            : 'bg-info'}"
                    >
                        {dmarcRecord.dkim_alignment}
                    </span>
                    {#if dmarcRecord.dkim_alignment === "relaxed"}
                        <div class="alert alert-info mt-2 mb-0 small">
                            <i class="bi bi-check-circle me-1"></i>
                            <strong>Recommended for most senders</strong> — ensures legitimate
                            subdomain mail passes.<br />
                            <i class="bi bi-exclamation-triangle me-1"></i>
                            For maximum brand protection, consider strict alignment (<code
                                >adkim=s</code
                            >) once your sending domains are standardized.
                        </div>
                    {:else}
                        <div class="alert alert-success mt-2 mb-0 small">
                            <i class="bi bi-shield-check me-1"></i>
                            <strong>Maximum brand protection</strong> — only exact domain matches are
                            accepted. Ensure all DKIM signatures use the exact From domain.
                        </div>
                    {/if}
                </div>
            {/if}

            <!-- Record -->
            {#if dmarcRecord.record}
                <div class="mb-2">
                    <strong>Record:</strong><br />
                    <code class="d-block mt-1 text-break">{dmarcRecord.record}</code>
                </div>
            {/if}

            <!-- Error -->
            {#if dmarcRecord.error}
                <div class="text-danger">
                    <strong>Error:</strong>
                    {dmarcRecord.error}
                </div>
            {/if}
        </div>
    </div>
{/if}
