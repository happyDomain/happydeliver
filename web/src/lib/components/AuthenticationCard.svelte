<script lang="ts">
    import type { Authentication, DNSResults, ReportSummary } from "$lib/api/types.gen";
    import { getScoreColorClass } from "$lib/score";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        authentication: Authentication;
        authenticationGrade?: string;
        authenticationScore?: number;
        dnsResults?: DNSResults;
    }

    let { authentication, authenticationGrade, authenticationScore, dnsResults }: Props = $props();

    function getAuthResultClass(result: string, noneIsFail: boolean): string {
        switch (result) {
            case "pass":
                return "text-success";
            case "fail":
            case "missing":
                return "text-danger";
            case "softfail":
            case "neutral":
                return "text-warning";
            case "declined":
                return "text-info";
            case "none":
                return noneIsFail ? "text-danger" : "text-muted";
            default:
                return "text-muted";
        }
    }

    function getAuthResultIcon(result: string, noneIsFail: boolean): string {
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
            case "declined":
                return "bi-dash-circle";
            case "none":
                return noneIsFail ? "bi-x-circle-fill" : "bi-question-circle";
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

<div class="card shadow-sm" id="authentication-details">
    <div class="card-header bg-white">
        <h4 class="mb-0 d-flex justify-content-between align-items-center">
            <span>
                <i class="bi bi-shield-check me-2"></i>
                Authentication
            </span>
            <span>
                {#if authenticationScore !== undefined}
                    <span class="badge bg-{getScoreColorClass(authenticationScore)}">
                        {authenticationScore}%
                    </span>
                {/if}
                {#if authenticationGrade !== undefined}
                    <GradeDisplay grade={authenticationGrade} size="small" />
                {/if}
            </span>
        </h4>
    </div>
    <div class="list-group list-group-flush">
            <!-- IPREV -->
            {#if authentication.iprev}
                <div class="list-group-item" id="authentication-iprev">
                    <div class="d-flex align-items-start">
                        <i class="bi {getAuthResultIcon(authentication.iprev.result, true)} {getAuthResultClass(authentication.iprev.result, true)} me-2 fs-5"></i>
                        <div>
                            <strong>IP Reverse DNS</strong>
                            <span class="text-uppercase ms-2 {getAuthResultClass(authentication.iprev.result, true)}">
                                {authentication.iprev.result}
                            </span>
                            {#if authentication.iprev.ip}
                                <div class="small">
                                    <strong>IP Address:</strong>
                                    <span class="text-muted">{authentication.iprev.ip}</span>
                                </div>
                            {/if}
                            {#if authentication.iprev.hostname}
                                <div class="small">
                                    <strong>Hostname:</strong>
                                    <span class="text-muted">{authentication.iprev.hostname}</span>
                                </div>
                            {/if}
                            {#if authentication.iprev.details}
                                <pre class="p-2 mb-0 bg-light text-muted small" style="white-space: pre-wrap">{authentication.iprev.details}</pre>
                            {/if}
                        </div>
                    </div>
                </div>
            {/if}

            <!-- SPF (Required) -->
            <div class="list-group-item">
                <div class="d-flex align-items-start" id="authentication-spf">
                    {#if authentication.spf}
                        <i class="bi {getAuthResultIcon(authentication.spf.result, true)} {getAuthResultClass(authentication.spf.result, true)} me-2 fs-5"></i>
                        <div>
                            <strong>SPF</strong>
                            <span class="text-uppercase ms-2 {getAuthResultClass(authentication.spf.result, true)}">
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
            <div class="list-group-item" id="authentication-dkim">
                <div class="d-flex align-items-start">
                    {#if authentication.dkim && authentication.dkim.length > 0}
                        <i class="bi {getAuthResultIcon(authentication.dkim[0].result, true)} {getAuthResultClass(authentication.dkim[0].result, true)} me-2 fs-5"></i>
                        <div>
                            <strong>DKIM</strong>
                            <span class="text-uppercase ms-2 {getAuthResultClass(authentication.dkim[0].result, true)}">
                                {authentication.dkim[0].result}
                            </span>
                            {#if authentication.dkim[0].domain}
                                <div class="small">
                                    <strong>Domain:</strong>
                                    <span class="text-muted">{authentication.dkim[0].domain}</span>
                                </div>
                            {/if}
                            {#if authentication.dkim[0].selector}
                                <div class="small">
                                    <strong>Selector:</strong>
                                    <span class="text-muted">{authentication.dkim[0].selector}</span>
                                </div>
                            {/if}
                            {#if authentication.dkim[0].details}
                                <pre class="p-2 mb-0 bg-light text-muted small" style="white-space: pre-wrap">{authentication.dkim[0].details}</pre>
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
            <div class="list-group-item" id="authentication-dmarc">
                <div class="d-flex align-items-start">
                    {#if authentication.dmarc}
                        <i class="bi {getAuthResultIcon(authentication.dmarc.result, true)} {getAuthResultClass(authentication.dmarc.result, true)} me-2 fs-5"></i>
                        <div>
                            <strong>DMARC</strong>
                            <span class="text-uppercase ms-2 {getAuthResultClass(authentication.dmarc.result, true)}">
                                {authentication.dmarc.result}
                            </span>
                            {#if authentication.dmarc.domain}
                                <div class="small">
                                    <strong>Domain:</strong>
                                    <span class="text-muted">{authentication.dmarc.domain}</span>
                                </div>
                            {/if}
                            {#snippet DMARCPolicy(policy)}
                                <div class="small">
                                    <strong>Policy:</strong>
                                    <span
                                        class="fw-bold"
                                        class:text-success={policy == "reject"}
                                        class:text-warning={policy == "quarantine"}
                                        class:text-danger={policy == "none"}
                                        class:bg-warning={policy != "none" && policy != "quarantine" && policy != "reject"}
                                    >
                                        {policy}
                                    </span>
                                </div>
                            {/snippet}
                            {#if authentication.dmarc.result != "none"}
                                {#if authentication.dmarc.details.indexOf("policy.published-domain-policy=") > 0}
                                    {@const policy = authentication.dmarc.details.replace(/^.*policy.published-domain-policy=([^\s]+).*$/, "$1")}
                                    {@render DMARCPolicy(policy)}
                                {:else if authentication.dmarc.domain}
                                    {@render DMARCPolicy(dnsResults.dmarc_record.policy)}
                                {/if}
                            {/if}
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
            <div class="list-group-item" id="authentication-bimi">
                <div class="d-flex align-items-start">
                    {#if authentication.bimi && authentication.bimi.result != "none"}
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
                    {:else if authentication.bimi && authentication.bimi.result == "none"}
                        <i class="bi bi-exclamation-circle-fill text-warning me-2 fs-5"></i>
                        <div>
                            <strong>BIMI</strong>
                            <span class="text-uppercase ms-2 text-warning">
                                NONE
                            </span>
                            <div class="text-muted small">Brand Indicators for Message Identification</div>
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
                <div class="list-group-item" id="authentication-arc">
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
