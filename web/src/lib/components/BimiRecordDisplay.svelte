<script lang="ts">
    import type { BimiCheck, BimiRecord, DmarcRecord } from "$lib/api/types.gen";

    interface Props {
        bimiRecord?: BimiRecord;
        dmarcRecord?: DmarcRecord;
    }

    let { bimiRecord, dmarcRecord }: Props = $props();

    const dmarcEnforced = $derived(
        dmarcRecord?.policy === "quarantine" || dmarcRecord?.policy === "reject",
    );

    function checkIcon(status: BimiCheck["status"]): string {
        switch (status) {
            case "pass":
                return "bi-check-circle-fill text-success";
            case "fail":
                return "bi-x-circle-fill text-danger";
            case "warning":
                return "bi-exclamation-triangle-fill text-warning";
            default:
                return "bi-dash-circle text-muted";
        }
    }

    function formatDate(date?: string): string {
        if (!date) return "";
        return new Date(date).toLocaleDateString();
    }
</script>

{#if bimiRecord}
    <div class="card mb-4" id="dns-bimi">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="text-muted mb-0">
                <i
                    class="bi"
                    class:bi-check-circle-fill={bimiRecord.valid}
                    class:text-success={bimiRecord.valid}
                    class:bi-x-circle-fill={!bimiRecord.valid}
                    class:text-danger={!bimiRecord.valid}
                ></i>
                Brand Indicators for Message Identification
            </h5>
            <span class="badge bg-secondary">BIMI</span>
        </div>
        <div class="card-body">
            <p class="card-text small text-muted mb-2">
                BIMI allows your brand logo to be displayed next to your emails in supported mail
                clients. Requires strong DMARC enforcement (quarantine or reject policy) and
                optionally a Verified Mark Certificate (VMC).
            </p>

            <hr />

            <div class="mb-2">
                <strong>Selector:</strong> <code>{bimiRecord.selector}</code>
                <strong class="ms-3">Domain:</strong> <code>{bimiRecord.domain}</code>
            </div>
            <div class="mb-2">
                <strong>Status:</strong>
                {#if bimiRecord.valid}
                    <span class="badge bg-success">Valid</span>
                {:else}
                    <span class="badge bg-danger">Invalid</span>
                {/if}
            </div>
            {#if bimiRecord.logo_url}
                <div class="mb-2">
                    <strong>Logo URL:</strong>
                    <a href={bimiRecord.logo_url} target="_blank" rel="noopener noreferrer"
                        >{bimiRecord.logo_url}</a
                    >
                </div>
            {/if}
            {#if bimiRecord.vmc_url}
                <div class="mb-2">
                    <strong>VMC URL:</strong>
                    <a href={bimiRecord.vmc_url} target="_blank" rel="noopener noreferrer"
                        >{bimiRecord.vmc_url}</a
                    >
                </div>
            {/if}
            {#if bimiRecord.record}
                <div class="mb-2">
                    <strong>Record:</strong><br />
                    <code class="d-block mt-1 text-break">{bimiRecord.record}</code>
                </div>
            {/if}
            {#if bimiRecord.error}
                <div class="text-danger">
                    <strong>Error:</strong>
                    {bimiRecord.error}
                </div>
            {/if}
            {#if bimiRecord.checks && bimiRecord.checks.length > 0}
                <hr />
                <h6 class="text-muted">Detailed checks</h6>
                <ul class="list-group list-group-flush">
                    {#each bimiRecord.checks as check (check.name)}
                        <li class="list-group-item px-0">
                            <i class="bi {checkIcon(check.status)} me-1"></i>
                            <strong>{check.description}</strong>
                            <span
                                class="badge ms-2"
                                class:bg-success={check.status === "pass"}
                                class:bg-danger={check.status === "fail"}
                                class:bg-warning={check.status === "warning"}
                                class:text-dark={check.status === "warning"}
                                class:bg-secondary={check.status === "skipped"}
                            >
                                {check.status}
                            </span>
                            {#if check.messages && check.messages.length > 0}
                                <ul class="small mb-0 mt-1">
                                    {#each check.messages as message (message)}
                                        <li
                                            class:text-danger={check.status === "fail"}
                                            class:text-warning={check.status === "warning"}
                                            class:text-muted={check.status === "skipped"}
                                        >
                                            {message}
                                        </li>
                                    {/each}
                                </ul>
                            {/if}
                        </li>
                    {/each}
                </ul>
            {/if}
            {#if bimiRecord.vmc}
                <hr />
                <h6 class="text-muted">Verified Mark Certificate</h6>
                <div class="small">
                    {#if bimiRecord.vmc.subject}
                        <div class="mb-1">
                            <strong>Subject:</strong>
                            <code class="text-break">{bimiRecord.vmc.subject}</code>
                        </div>
                    {/if}
                    {#if bimiRecord.vmc.issuer}
                        <div class="mb-1">
                            <strong>Issuer:</strong>
                            <code class="text-break">{bimiRecord.vmc.issuer}</code>
                        </div>
                    {/if}
                    {#if bimiRecord.vmc.not_before && bimiRecord.vmc.not_after}
                        <div class="mb-1">
                            <strong>Validity:</strong>
                            {formatDate(bimiRecord.vmc.not_before)} &mdash; {formatDate(
                                bimiRecord.vmc.not_after,
                            )}
                        </div>
                    {/if}
                    {#if bimiRecord.vmc.san_domains && bimiRecord.vmc.san_domains.length > 0}
                        <div class="mb-1">
                            <strong>Covered domains:</strong>
                            {#each bimiRecord.vmc.san_domains as san (san)}
                                <code class="me-1">{san}</code>
                            {/each}
                        </div>
                    {/if}
                    <div class="mb-1">
                        <strong>BIMI Extended Key Usage:</strong>
                        {#if bimiRecord.vmc.has_bimi_eku}
                            <span class="badge bg-success">present</span>
                        {:else}
                            <span class="badge bg-danger">missing</span>
                        {/if}
                        <strong class="ms-3">Embedded logo:</strong>
                        {#if bimiRecord.vmc.has_logotype}
                            <span class="badge bg-success">present</span>
                            {#if bimiRecord.vmc.logo_matches === true}
                                <span class="badge bg-success ms-1">matches published logo</span>
                            {:else if bimiRecord.vmc.logo_matches === false}
                                <span class="badge bg-danger ms-1"
                                    >differs from published logo</span
                                >
                            {/if}
                        {:else}
                            <span class="badge bg-danger">missing</span>
                        {/if}
                    </div>
                </div>
            {/if}
            {#if !bimiRecord.valid && dmarcEnforced}
                <div class="alert alert-info mt-3 mb-0">
                    <h6 class="alert-heading">
                        <i class="bi bi-lightbulb me-1"></i>
                        Explicitly decline BIMI participation
                    </h6>
                    <p class="mb-2 small">
                        If you do not intend to publish a brand logo, you can add a declination
                        record to signal that this domain deliberately opts out of BIMI. This
                        prevents mail clients from falling back to a parent-domain record:
                    </p>
                    <code class="d-block bg-white rounded p-2 text-break border"
                        >{bimiRecord.selector}._bimi.{bimiRecord.domain}. IN TXT "v=BIMI1; l=; a="</code
                    >
                    <p class="mt-1 mb-0 small text-muted">
                        Declination record format as defined in §&thinsp;4.3.1 of
                        <em>draft-brand-indicators-for-message-identification</em>.
                    </p>
                </div>
            {/if}
        </div>
    </div>
{/if}
