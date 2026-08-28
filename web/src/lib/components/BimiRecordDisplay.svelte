<script lang="ts">
    import type {
        BimiCheck,
        BimiRecord,
        DmarcRecord,
        SchemasBimiCheckMessage,
    } from "$lib/api/types.gen";

    interface Props {
        bimiRecord?: BimiRecord;
        dmarcRecord?: DmarcRecord;
    }

    let { bimiRecord, dmarcRecord }: Props = $props();

    const dmarcEnforced = $derived(
        dmarcRecord?.policy === "quarantine" || dmarcRecord?.policy === "reject",
    );

    let checksOpen = $state(false);
    let vmcOpen = $state(false);

    type Status = BimiCheck["status"];

    type Dot = { status: Status; label: string };

    /* Dots in the same order as the entries of the expanded view. */
    const checksDots: Dot[] = $derived(
        (bimiRecord?.checks ?? []).map((c) => ({
            status: c.status,
            label: c.description ?? c.name,
        })),
    );

    /* Optional booleans are left unset when the criterion could not be
       evaluated (e.g. the certificate could not be downloaded or parsed);
       that is not the same as the criterion being absent. */
    function triState(value: boolean | undefined): Status {
        if (value === undefined) return "skipped";
        return value ? "pass" : "fail";
    }

    const vmcDots: Dot[] = $derived.by(() => {
        const vmc = bimiRecord?.vmc;
        if (!vmc) return [];

        const dots: Dot[] = [
            { status: triState(vmc.has_bimi_eku), label: "BIMI Extended Key Usage" },
            { status: triState(vmc.has_logotype), label: "Embedded logo" },
        ];
        if (vmc.logo_matches !== undefined) {
            dots.push({
                status: vmc.logo_matches ? "pass" : "fail",
                label: "Embedded logo matches published logo",
            });
        }

        return dots;
    });

    /* How each status is painted, in one place: the dots, the icons and the
       badges all read it, so a status cannot end up a different colour
       depending on which of the three renders it. */
    const STATUS: Record<Status, { badge: string; icon: string; text: string }> = {
        pass: { badge: "bg-success", icon: "bi-check-circle-fill", text: "text-success" },
        fail: { badge: "bg-danger", icon: "bi-x-circle-fill", text: "text-danger" },
        warning: {
            badge: "bg-warning text-dark",
            icon: "bi-exclamation-triangle-fill",
            text: "text-warning",
        },
        skipped: { badge: "bg-secondary", icon: "bi-dash-circle", text: "text-muted" },
    };

    function messageColor(message: SchemasBimiCheckMessage): string {
        if (message.severity === "info") return "text-muted";
        return message.severity === "warning" ? "text-warning" : "text-danger";
    }

    function formatDate(date?: string): string {
        if (!date) return "";
        return new Date(date).toLocaleDateString();
    }
</script>

{#snippet statusDots(dots: Dot[])}
    <span
        class="badge bg-light border rounded-pill d-inline-flex align-items-center gap-1 py-1 px-2"
    >
        {#each dots as dot, i (i)}
            <span
                class="status-dot rounded-circle {STATUS[dot.status].badge}"
                title="{dot.label}: {dot.status}"
            ></span>
        {/each}
    </span>
{/snippet}

<!-- The three states an optional criterion has: unevaluated is not failed, so
     it must never render as a failure. -->
{#snippet presenceBadge(
    value: boolean | undefined,
    passLabel: string = "present",
    failLabel: string = "missing",
)}
    {#if value === undefined}
        <span class="badge bg-secondary">not evaluated</span>
    {:else if value}
        <span class="badge bg-success">{passLabel}</span>
    {:else}
        <span class="badge bg-danger">{failLabel}</span>
    {/if}
{/snippet}

<!-- The disclosure header both collapsible sections share: a chevron, a
     heading, and the collapsed section's verdicts folded into dots. -->
{#snippet collapseHeader(
    open: boolean,
    controls: string,
    title: string,
    dots: Dot[],
    toggle: () => void,
)}
    <button
        type="button"
        class="btn btn-link p-0 text-decoration-none text-muted d-flex align-items-center w-100"
        aria-expanded={open}
        aria-controls={controls}
        onclick={toggle}
    >
        <i class="bi me-1" class:bi-chevron-right={!open} class:bi-chevron-down={open}></i>
        <h6 class="mb-0 me-2">{title}</h6>
        {#if !open}
            {@render statusDots(dots)}
        {/if}
    </button>
{/snippet}

{#if bimiRecord}
    <div class="card mb-4" id="dns-bimi">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="text-muted mb-0">
                <i
                    class="bi"
                    class:bi-check-circle-fill={bimiRecord.valid}
                    class:text-success={bimiRecord.valid}
                    class:bi-exclamation-triangle-fill={bimiRecord.record_valid &&
                        !bimiRecord.valid}
                    class:text-warning={bimiRecord.record_valid && !bimiRecord.valid}
                    class:bi-x-circle-fill={!bimiRecord.record_valid}
                    class:text-danger={!bimiRecord.record_valid}
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
                <strong>DNS record:</strong>
                {#if bimiRecord.record_valid}
                    <span class="badge bg-success">Valid</span>
                {:else}
                    <span class="badge bg-danger">Invalid</span>
                {/if}
            </div>
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
            {#if bimiRecord.logo_url}
                <div class="mb-2">
                    <strong>Logo URL:</strong>
                    <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- external URL, not a SvelteKit route -->
                    <a href={bimiRecord.logo_url} target="_blank" rel="noopener noreferrer"
                        >{bimiRecord.logo_url}</a
                    >
                </div>
            {/if}
            {#if bimiRecord.vmc_url}
                <div class="mb-2">
                    <strong>VMC URL:</strong>
                    <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- external URL, not a SvelteKit route -->
                    <a href={bimiRecord.vmc_url} target="_blank" rel="noopener noreferrer"
                        >{bimiRecord.vmc_url}</a
                    >
                </div>
            {/if}
            {#if bimiRecord.record_valid}
                <div class="mb-2">
                    <strong>Assets (logo, VMC):</strong>
                    {#if bimiRecord.valid}
                        <span class="badge bg-success">Compliant</span>
                    {:else}
                        <span class="badge bg-danger">Failed validation</span>
                    {/if}
                </div>
            {/if}
            {#if bimiRecord.checks && bimiRecord.checks.length > 0}
                <hr />
                {@render collapseHeader(
                    checksOpen,
                    "bimi-detailed-checks",
                    "Detailed checks",
                    checksDots,
                    () => (checksOpen = !checksOpen),
                )}
                <ul
                    id="bimi-detailed-checks"
                    class="list-group list-group-flush mt-2"
                    class:d-none={!checksOpen}
                >
                    {#each bimiRecord.checks as check (check.name)}
                        <li class="list-group-item px-0">
                            <i
                                class="bi {STATUS[check.status].icon} {STATUS[check.status]
                                    .text} me-1"
                            ></i>
                            <strong>{check.description}</strong>
                            <span class="badge ms-2 {STATUS[check.status].badge}">
                                {check.status}
                            </span>
                            {#if check.messages && check.messages.length > 0}
                                <ul class="small mb-0 mt-1">
                                    {#each check.messages as message, i (i)}
                                        <li class={messageColor(message)}>
                                            {#if message.severity === "warning" && check.status === "fail"}
                                                <i
                                                    class="bi bi-exclamation-triangle-fill me-1"
                                                    title="Warning (does not cause the failure)"
                                                ></i>
                                            {/if}
                                            {message.text}
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
                {@render collapseHeader(
                    vmcOpen,
                    "bimi-vmc-details",
                    "Verified Mark Certificate",
                    vmcDots,
                    () => (vmcOpen = !vmcOpen),
                )}
                <div id="bimi-vmc-details" class="small mt-2" class:d-none={!vmcOpen}>
                    {#if bimiRecord.vmc.error}
                        <div class="alert alert-danger py-1 px-2 mb-2 small">
                            {bimiRecord.vmc.error}
                        </div>
                    {/if}
                    {#if bimiRecord.vmc.subject}
                        <div class="mb-1 text-truncate">
                            <strong>Subject:</strong>
                            <code class="text-break" title={bimiRecord.vmc.subject}>
                                {bimiRecord.vmc.subject}
                            </code>
                        </div>
                    {/if}
                    {#if bimiRecord.vmc.issuer}
                        <div class="mb-1 text-truncate">
                            <strong>Issuer:</strong>
                            <code class="text-break" title={bimiRecord.vmc.issuer}>
                                {bimiRecord.vmc.issuer}
                            </code>
                        </div>
                    {/if}
                    {#if bimiRecord.vmc.not_before && bimiRecord.vmc.not_after}
                        <div class="mb-1">
                            <strong>Validity:</strong>
                            {formatDate(bimiRecord.vmc.not_before)} &rarr; {formatDate(
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
                        {@render presenceBadge(bimiRecord.vmc.has_bimi_eku)}
                        <strong class="ms-3">Embedded logo:</strong>
                        {@render presenceBadge(bimiRecord.vmc.has_logotype)}
                        {#if bimiRecord.vmc.logo_matches === true}
                            <span class="badge bg-success ms-1">matches published logo</span>
                        {:else if bimiRecord.vmc.logo_matches === false}
                            <span class="badge bg-danger ms-1">differs from published logo</span>
                        {/if}
                    </div>
                </div>
            {/if}
            {#if !bimiRecord.record && dmarcEnforced}
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

<style>
    .status-dot {
        display: inline-block;
        width: 0.5rem;
        height: 0.5rem;
    }
</style>
