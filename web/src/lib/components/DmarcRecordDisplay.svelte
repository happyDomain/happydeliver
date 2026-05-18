<script lang="ts">
    import type { DmarcRecord } from "$lib/api/types.gen";

    interface Props {
        dmarcRecord?: DmarcRecord;
        fromDomain?: string;
    }

    let { dmarcRecord, fromDomain }: Props = $props();

    const isFallback = $derived(
        !!dmarcRecord?.domain && !!fromDomain && dmarcRecord.domain !== fromDomain,
    );
    // A single-label domain (no dot) is a TLD/PSD level fallback
    const isPsdFallback = $derived(isFallback && !dmarcRecord?.domain?.includes("."));

    // Helper function to determine policy strength
    const policyStrength = (policy: string | undefined): number => {
        const strength: Record<string, number> = { none: 0, quarantine: 1, reject: 2 };
        return strength[policy || "none"] || 0;
    };

    // Effective policy after applying DMARCbis t=y downgrade
    const effectivePolicy = $derived((): string => {
        const p = dmarcRecord?.policy ?? "none";
        if (!dmarcRecord?.test_mode) return p;
        if (p === "reject") return "quarantine";
        if (p === "quarantine") return "none";
        return p;
    });
</script>

{#if dmarcRecord}
    <div class="card mb-4" id="dns-dmarc">
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
                DMARC enforces domain alignment requirements (regardless of the policy). It builds
                on SPF and DKIM by telling receiving servers what to do with emails that fail
                authentication checks. It also enables reporting so you can monitor your email
                security.
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

            <!-- Fallback domain notice -->
            {#if isFallback}
                <div class="mb-3">
                    <strong>Record found at:</strong>
                    <code>{dmarcRecord.domain}</code>
                    <div class="alert alert-info mt-2 mb-0 small">
                        <i class="bi bi-info-circle me-1"></i>
                        No DMARC record exists for <code>{fromDomain}</code>. The record above was
                        inherited from
                        {#if isPsdFallback}
                            the Public Suffix Domain <code>{dmarcRecord.domain}</code> via the DMARCbis
                            DNS Tree Walk (which obsoletes the RFC 9091 PSD DMARC experiment).
                        {:else}
                            the organizational domain <code>{dmarcRecord.domain}</code> via the
                            DMARCbis DNS Tree Walk (compatible with RFC 7489 organizational domain
                            fallback).
                        {/if}
                    </div>
                </div>
            {/if}

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

            <!-- Test Mode (DMARCbis t= tag) -->
            {#if dmarcRecord.test_mode}
                <div class="mb-3">
                    <strong>Test Mode:</strong>
                    <span class="badge bg-warning">t=y (active)</span>
                    <div class="alert alert-warning mt-2 mb-0 small">
                        <i class="bi bi-flask me-1"></i>
                        <strong>Test mode active</strong> — DMARCbis-compliant receivers will
                        downgrade the effective policy one level:
                        {#if dmarcRecord.policy === "reject"}
                            <code>p=reject</code> is applied as <code>p=quarantine</code>.
                        {:else if dmarcRecord.policy === "quarantine"}
                            <code>p=quarantine</code> is applied as <code>p=none</code> (no action taken).
                        {:else}
                            <code>p=none</code> is unaffected by test mode.
                        {/if}
                        Aggregate reports are still generated normally.
                        This tag replaces the deprecated <code>pct=</code> for gradual rollout.
                    </div>
                </div>
            {/if}

            <!-- PSD tag (DMARCbis psd=) -->
            {#if dmarcRecord.psd === "y"}
                <div class="mb-3">
                    <strong>Public Suffix Domain:</strong>
                    <span class="badge bg-info">psd=y</span>
                    <div class="alert alert-info mt-2 mb-0 small">
                        <i class="bi bi-info-circle me-1"></i>
                        <strong>PSD declared</strong> — this domain is declared as a Public Suffix
                        Domain. DMARCbis-compliant receivers will apply this policy to subdomains
                        that have no DMARC record of their own when using the DNS Tree Walk algorithm.
                    </div>
                </div>
            {:else if dmarcRecord.psd === "n"}
                <div class="mb-3">
                    <strong>Organizational Domain Boundary:</strong>
                    <span class="badge bg-info">psd=n</span>
                    <div class="alert alert-info mt-2 mb-0 small">
                        <i class="bi bi-info-circle me-1"></i>
                        <strong>Org Domain declared</strong> — <code>psd=n</code> explicitly declares
                        this as an Organizational Domain boundary. Subdomains with separate DNS
                        delegation will use their own independent DMARCbis Tree Walk.
                    </div>
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

            <!-- Non-Existent Subdomain Policy (np tag, DMARCbis) -->
            {#if dmarcRecord.nonexistent_subdomain_policy}
                {@const effectiveSubStrength = policyStrength(dmarcRecord.subdomain_policy ?? dmarcRecord.policy)}
                {@const npStrength = policyStrength(dmarcRecord.nonexistent_subdomain_policy)}
                <div class="mb-3">
                    <strong>Non-Existent Subdomain Policy:</strong>
                    <span
                        class="badge {dmarcRecord.nonexistent_subdomain_policy === 'reject'
                            ? 'bg-success'
                            : dmarcRecord.nonexistent_subdomain_policy === 'quarantine'
                              ? 'bg-warning'
                              : 'bg-secondary'}"
                    >
                        {dmarcRecord.nonexistent_subdomain_policy}
                    </span>
                    {#if npStrength >= effectiveSubStrength}
                        <div class="alert alert-success mt-2 mb-0 small">
                            <i class="bi bi-check-circle me-1"></i>
                            <strong>Good configuration</strong> — non-existent subdomain policy is equal to or stricter
                            than the effective subdomain policy.
                        </div>
                    {:else}
                        <div class="alert alert-warning mt-2 mb-0 small">
                            <i class="bi bi-exclamation-triangle me-1"></i>
                            <strong>Weaker protection for non-existent subdomains</strong> — consider setting
                            <code>np={dmarcRecord.subdomain_policy ?? dmarcRecord.policy}</code> to match your subdomain policy.
                        </div>
                    {/if}
                    <div class="alert alert-info mt-2 mb-0 small">
                        <i class="bi bi-info-circle me-1"></i>
                        The <code>np=</code> tag is introduced by <strong>DMARCbis</strong> (draft-ietf-dmarc-dmarcbis),
                        a draft RFC updating RFC 7489. Support may vary across mail receivers.
                    </div>
                </div>
            {/if}

            <!-- Percentage (pct=, deprecated in DMARCbis) -->
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
                    <div class="alert alert-warning mt-2 mb-0 small">
                        <i class="bi bi-exclamation-triangle me-1"></i>
                        <strong>Deprecated tag</strong> — the <code>pct=</code> tag is removed in
                        DMARCbis. Many receivers already ignore it. For gradual rollout, replace it
                        with <code>t=y</code> (test mode); for full enforcement, simply remove
                        <code>pct=</code> from your record.
                        {#if dmarcRecord.percentage === 0}
                            <br /><strong>pct=0 is an anti-pattern</strong> — it was widely misused
                            as a signal to bypass DMARC entirely, which is one reason the tag was
                            removed. Use <code>t=y</code> instead.
                        {/if}
                    </div>
                    {#if dmarcRecord.percentage === 100}
                        <div class="alert alert-success mt-2 mb-0 small">
                            <i class="bi bi-check-circle me-1"></i>
                            <strong>Full enforcement</strong> — all messages are subject to DMARC policy.
                        </div>
                    {:else if dmarcRecord.percentage > 0 && dmarcRecord.percentage >= 50}
                        <div class="alert alert-warning mt-2 mb-0 small">
                            <i class="bi bi-exclamation-triangle me-1"></i>
                            <strong>Partial enforcement</strong> — only {dmarcRecord.percentage}% of
                            messages are subject to DMARC policy. Receivers ignoring pct= will apply
                            the full policy regardless.
                        </div>
                    {:else if dmarcRecord.percentage > 0}
                        <div class="alert alert-danger mt-2 mb-0 small">
                            <i class="bi bi-x-circle me-1"></i>
                            <strong>Low enforcement</strong> — only {dmarcRecord.percentage}% of
                            messages are protected. Receivers ignoring pct= will apply full policy.
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

            <!-- Deprecated rf=/ri= tags -->
            {#if dmarcRecord.deprecated_rf || dmarcRecord.deprecated_ri}
                <div class="alert alert-warning mt-2 mb-3 small">
                    <i class="bi bi-exclamation-triangle me-1"></i>
                    <strong>Deprecated tags detected</strong> — your record contains
                    {#if dmarcRecord.deprecated_rf && dmarcRecord.deprecated_ri}
                        <code>rf=</code> and <code>ri=</code> tags that are
                    {:else if dmarcRecord.deprecated_rf}
                        the <code>rf=</code> tag that is
                    {:else}
                        the <code>ri=</code> tag that is
                    {/if}
                    removed in DMARCbis. Modern receivers will ignore
                    {dmarcRecord.deprecated_rf && dmarcRecord.deprecated_ri ? "them" : "it"}.
                    {#if dmarcRecord.deprecated_ri}
                        Aggregate reporting interval is now fixed at ≥ 24 hours regardless of
                        <code>ri=</code>.
                    {/if}
                    You can safely remove
                    {dmarcRecord.deprecated_rf && dmarcRecord.deprecated_ri ? "these tags" : "this tag"}
                    from your DMARC record.
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
