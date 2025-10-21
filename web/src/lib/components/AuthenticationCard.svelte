<script lang="ts">
    import type { Authentication, ReportSummary } from "$lib/api/types.gen";

    interface Props {
        authentication: Authentication;
        authenticationScore?: number;
    }

    let { authentication, authenticationScore }: Props = $props();

    function getAuthResultClass(result: string): string {
        switch (result) {
            case "pass":
                return "text-success";
            case "fail":
            case "missing":
                return "text-danger";
            case "softfail":
            case "neutral":
                return "text-warning";
            default:
                return "text-muted";
        }
    }

    function getAuthResultIcon(result: string): string {
        switch (result) {
            case "pass":
                return "bi-check-circle-fill";
            case "fail":
                return "bi-x-circle-fill";
            case "softfail":
            case "neutral":
                return "bi-exclamation-circle-fill";
            case "missing":
                return "bi-dash-circle-fill";
            default:
                return "bi-question-circle";
        }
    }

    function getAuthResultText(result: string): string {
        switch (result) {
            case "missing":
                return "Not configured";
            default:
                return result;
        }
    }
</script>

<div class="card shadow-sm">
    <div class="card-header bg-white">
        <h4 class="mb-0 d-flex justify-content-between align-items-center">
            <span>
                <i class="bi bi-shield-check me-2"></i>
                Authentication
            </span>
            {#if authenticationScore !== undefined}
                <span class="badge bg-secondary">
                    {authenticationScore}%
                </span>
            {/if}
        </h4>
    </div>
    <div class="card-body">
        <div class="row row-cols-1">
            <!-- SPF (Required) -->
            <div class="col mb-3">
                <div class="d-flex align-items-start">
                    {#if authentication.spf}
                        <i class="bi {getAuthResultIcon(authentication.spf.result)} {getAuthResultClass(authentication.spf.result)} me-2 fs-5"></i>
                        <div>
                            <strong>SPF</strong>
                            <span class="text-uppercase ms-2 {getAuthResultClass(authentication.spf.result)}">
                                {authentication.spf.result}
                            </span>
                            {#if authentication.spf.domain}
                                <div class="small">
                                    <strong>Domain:</strong>
                                    <span class="text-muted">{authentication.spf.domain}</span>
                                </div>
                            {/if}
                            {#if authentication.spf.details}
                                <pre class="p-2 mb-0 bg-light text-muted small" style="white-space: pre-wrap">{authentication.spf.details}</pre>
                            {/if}
                        </div>
                    {:else}
                        <i class="bi {getAuthResultIcon('missing')} {getAuthResultClass('missing')} me-2 fs-5"></i>
                        <div>
                            <strong>SPF</strong>
                            <span class="text-uppercase ms-2 {getAuthResultClass('missing')}">
                                {getAuthResultText('missing')}
                            </span>
                            <div class="text-muted small">SPF record is required for proper email authentication</div>
                        </div>
                    {/if}
                </div>
            </div>

            <!-- DKIM (Required) -->
            <div class="col mb-3">
                <div class="d-flex align-items-start">
                    {#if authentication.dkim && authentication.dkim.length > 0}
                        <i class="bi {getAuthResultIcon(authentication.dkim[0].result)} {getAuthResultClass(authentication.dkim[0].result)} me-2 fs-5"></i>
                        <div>
                            <strong>DKIM</strong>
                            <span class="text-uppercase ms-2 {getAuthResultClass(authentication.dkim[0].result)}">
                                {authentication.dkim[0].result}
                            </span>
                            {#if authentication.dkim[0].domain}
                                <div class="text-muted small">{authentication.dkim[0].domain}</div>
                            {/if}
                            {#if authentication.dkim[0].selector}
                                <div class="text-muted small">Selector: {authentication.dkim[0].selector}</div>
                            {/if}
                            {#if authentication.dkim.details}
                                <pre class="p-2 mb-0 bg-light text-muted small" style="white-space: pre-wrap">{authentication.dkim.details}</pre>
                            {/if}
                        </div>
                    {:else}
                        <i class="bi {getAuthResultIcon('missing')} {getAuthResultClass('missing')} me-2 fs-5"></i>
                        <div>
                            <strong>DKIM</strong>
                            <span class="text-uppercase ms-2 {getAuthResultClass('missing')}">
                                {getAuthResultText('missing')}
                            </span>
                            <div class="text-muted small">DKIM signature is required for proper email authentication</div>
                        </div>
                    {/if}
                </div>
            </div>

            <!-- DMARC (Required) -->
            <div class="col mb-3">
                <div class="d-flex align-items-start">
                    {#if authentication.dmarc}
                        <i class="bi {getAuthResultIcon(authentication.dmarc.result)} {getAuthResultClass(authentication.dmarc.result)} me-2 fs-5"></i>
                        <div>
                            <strong>DMARC</strong>
                            <span class="text-uppercase ms-2 {getAuthResultClass(authentication.dmarc.result)}">
                                {authentication.dmarc.result}
                            </span>
                            {#if authentication.dmarc.details}
                                <pre class="p-2 mb-0 bg-light text-muted small" style="white-space: pre-wrap">{authentication.dmarc.details}</pre>
                            {/if}
                        </div>
                    {:else}
                        <i class="bi {getAuthResultIcon('missing')} {getAuthResultClass('missing')} me-2 fs-5"></i>
                        <div>
                            <strong>DMARC</strong>
                            <span class="text-uppercase ms-2 {getAuthResultClass('missing')}">
                                {getAuthResultText('missing')}
                            </span>
                            <div class="text-muted small">DMARC policy is required for proper email authentication</div>
                        </div>
                    {/if}
                </div>
            </div>

            <!-- BIMI (Optional) -->
            <div class="col mb-3">
                <div class="d-flex align-items-start">
                    {#if authentication.bimi}
                        <i class="bi {getAuthResultIcon(authentication.bimi.result)} {getAuthResultClass(authentication.bimi.result)} me-2 fs-5"></i>
                        <div>
                            <strong>BIMI</strong>
                            <span class="text-uppercase ms-2 {getAuthResultClass(authentication.bimi.result)}">
                                {authentication.bimi.result}
                            </span>
                            {#if authentication.bimi.details}
                                <pre class="p-2 mb-0 bg-light text-muted small" style="white-space: pre-wrap">{authentication.bimi.details}</pre>
                            {/if}
                        </div>
                    {:else}
                        <i class="bi bi-info-circle text-muted me-2 fs-5"></i>
                        <div>
                            <strong>BIMI</strong>
                            <span class="text-uppercase ms-2 text-muted">
                                Optional
                            </span>
                            <div class="text-muted small">Brand Indicators for Message Identification (optional enhancement)</div>
                        </div>
                    {/if}
                </div>
            </div>

            <!-- ARC (Optional) -->
            {#if authentication.arc}
                <div class="col mb-3">
                    <div class="d-flex align-items-start">
                        <i class="bi {getAuthResultIcon(authentication.arc.result)} {getAuthResultClass(authentication.arc.result)} me-2 fs-5"></i>
                        <div>
                            <strong>ARC</strong>
                            <span class="text-uppercase ms-2 {getAuthResultClass(authentication.arc.result)}">
                                {authentication.arc.result}
                            </span>
                            {#if authentication.arc.chain_length}
                                <div class="text-muted small">Chain length: {authentication.arc.chain_length}</div>
                            {/if}
                            {#if authentication.arc.details}
                                <pre class="p-2 mb-0 bg-light text-muted small" style="white-space: pre-wrap">{authentication.arc.details}</pre>
                            {/if}
                        </div>
                    </div>
                </div>
            {/if}
        </div>
    </div>
</div>
