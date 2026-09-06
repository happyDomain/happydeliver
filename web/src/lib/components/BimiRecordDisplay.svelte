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

    /* Only consulted when no BIMI record exists at all, to offer the
       declination advice below. The authoritative dmarc_enforcement check is
       not available there: the analyser only runs the checks on a record it
       found, so this is the raw policy rather than a second opinion on it. */
    const dmarcEnforced = $derived(
        dmarcRecord?.policy === "quarantine" || dmarcRecord?.policy === "reject",
    );

    let checksOpen = $state(false);
    let vmcOpen = $state(false);

    type Status = BimiCheck["status"];

    /* The card headline grades the configuration on the same three tiers as
       the verdict of the BIMI page, so the two cannot contradict each other.
       Assets that fail are graded as harshly as a record that does not parse:
       an Indicator receivers cannot validate is one they do not display, so
       either way nothing is shown. The intermediate tier is the record that
       works but asserts its Indicator without a certificate to vouch for it,
       which the providers holding most of the inboxes will not act on. */
    const selfAsserted = $derived(
        !bimiRecord?.vmc_url &&
            (bimiRecord?.checks?.some((c) => c.name === "vmc" && c.status === "warning") ?? false),
    );

    const headline: Status = $derived(
        !bimiRecord?.record_valid || !bimiRecord?.valid
            ? "fail"
            : selfAsserted
              ? "warning"
              : "pass",
    );

    type Dot = { status: Status; label: string };

    /* Set when the record was found at the organizational domain because the
       queried domain publishes none of its own: it applies here, but it is not
       this domain's to control. */
    const inheritedFrom: string | undefined = $derived(
        bimiRecord?.record_domain && bimiRecord.record_domain !== bimiRecord.domain
            ? bimiRecord.record_domain
            : undefined,
    );

    /* Set when the record shown is not the one the requested selector points
       at, because its lps= tag sent discovery to a selector named after the
       sender's address. */
    const derivedFromLocalPart: boolean = $derived(
        !!bimiRecord?.requested_selector && bimiRecord.requested_selector !== bimiRecord.selector,
    );

    /* How the lps= tag describes the senders it applies to. An empty prefix
       list is not the absence of a list: it means every local-part. */
    const localPartScope: string | undefined = $derived.by(() => {
        if (!bimiRecord?.local_part_selector) return undefined;
        const prefixes = bimiRecord.local_part_prefixes ?? [];
        if (prefixes.length === 0) return "every sending address";
        return `the addresses starting with ${prefixes.map((p) => `“${p}”`).join(", ")}`;
    });

    /* Why section 7.1 forbids BIMI processing here, as the analyser decided
       it: a record and assets that are fully compliant still display nothing
       when the DMARC policy is not at enforcement. The reasons are read off
       the check rather than recomputed from dmarcRecord, so this banner cannot
       drift from the verdict the rest of the report shows. */
    const dmarcBlockers: string[] = $derived.by(() => {
        const check = bimiRecord?.checks?.find((c) => c.name === "dmarc_enforcement");
        if (check?.status !== "fail") return [];
        return (check.messages ?? []).filter((m) => m.severity === "error").map((m) => m.text);
    });

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
            { status: triState(vmc.issuer_has_bimi_eku), label: "Issuer allowed to issue VMCs" },
            { status: triState(vmc.has_logotype), label: "Embedded logo" },
            {
                status: triState(vmc.logo_hash_verified),
                label: "Embedded logo matches its certified hash",
            },
            { status: triState(vmc.has_crl_distribution_points), label: "Revocation checkable" },
            {
                status: triState(vmc.sct_count === undefined ? undefined : vmc.sct_count > 0),
                label: "Logged to Certificate Transparency",
            },
        ];

        /* Two criteria only an analysis that had both sides to compare could
           reach: without the published logo, or without a set of trusted
           roots, a permanently grey dot would read as a failing criterion
           rather than as one that was never asked. */
        if (vmc.logo_matches !== undefined) {
            dots.push({
                status: triState(vmc.logo_matches),
                label: "Embedded logo matches published logo",
            });
        }
        if (vmc.chain_trusted !== undefined) {
            dots.push({
                status: triState(vmc.chain_trusted),
                label: "Chain leads to a trusted BIMI root",
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
                    class:bi-check-circle-fill={headline === "pass"}
                    class:text-success={headline === "pass"}
                    class:bi-exclamation-triangle-fill={headline === "warning"}
                    class:text-warning={headline === "warning"}
                    class:bi-x-circle-fill={headline === "fail"}
                    class:text-danger={headline === "fail"}
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
            {#if dmarcBlockers.length > 0}
                <div class="alert alert-danger">
                    <h6 class="alert-heading">
                        <i class="bi bi-exclamation-octagon-fill me-1"></i>
                        This logo will not be displayed
                    </h6>
                    <p class="mb-2 small">
                        A message is only considered for BIMI once the sending domain's DMARC policy
                        is at enforcement. Receivers must not perform BIMI processing here, so no
                        indicator is shown however compliant the record and the logo below are.
                    </p>
                    <ul class="mb-2 small">
                        {#each dmarcBlockers as reason, i (i)}
                            <li>{reason}</li>
                        {/each}
                    </ul>
                    <p class="mb-0 small text-muted">
                        Requirement from §&thinsp;7.1 of
                        <em>draft-brand-indicators-for-message-identification</em>. See the
                        <a href="#dns-dmarc" class="alert-link">DMARC section</a> of this report.
                    </p>
                </div>
            {/if}
            {#if inheritedFrom}
                <div class="alert alert-info py-2">
                    <i class="bi bi-diagram-2 me-1"></i>
                    <code>{bimiRecord.domain}</code> publishes no BIMI record of its own: the one
                    shown below is inherited from its organizational domain
                    <code>{inheritedFrom}</code>. Publish a record at
                    <code>{bimiRecord.selector}._bimi.{bimiRecord.domain}</code> to give this domain its
                    own indicator, or a declination record to opt it out.
                </div>
            {/if}
            {#if derivedFromLocalPart}
                <div class="alert alert-info py-2">
                    <i class="bi bi-person-badge me-1"></i>
                    The record published at
                    <code
                        >{bimiRecord.requested_selector}._bimi.{bimiRecord.record_domain ??
                            bimiRecord.domain}</code
                    >
                    sends this sender to a selector named after its address, so the indicator shown below
                    is the one published at
                    <code
                        >{bimiRecord.selector}._bimi.{bimiRecord.record_domain ??
                            bimiRecord.domain}</code
                    >.
                </div>
            {:else if localPartScope}
                <div class="alert alert-info py-2">
                    <i class="bi bi-person-badge me-1"></i>
                    This record's <code>lps=</code> tag sends {localPartScope} to a selector named after
                    the address, so those senders can be served another indicator than the one shown below.
                </div>
            {/if}
            {#if bimiRecord.avatar_preference}
                <div class="mb-2">
                    <strong>Avatar preference:</strong>
                    <code>{bimiRecord.avatar_preference}</code>
                    <span class="small text-muted ms-1">
                        {#if bimiRecord.avatar_preference === "personal"}
                            providers that display personal avatars are asked to prefer the sender's
                            avatar over the brand indicator.
                        {:else if bimiRecord.avatar_preference === "brand"}
                            providers that display personal avatars are asked to prefer the brand
                            indicator. This is also the default.
                        {:else}
                            unknown value: receivers must ignore it and fall back to
                            <code>brand</code>, and some may treat the whole record as failing.
                        {/if}
                    </span>
                </div>
            {/if}
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
                        {#if bimiRecord.vmc.logo_media_type}
                            <span class="badge bg-secondary ms-1"
                                >{bimiRecord.vmc.logo_media_type}</span
                            >
                        {/if}
                        {#if bimiRecord.vmc.logo_matches === true}
                            <span class="badge bg-success ms-1">matches published logo</span>
                        {:else if bimiRecord.vmc.logo_matches === false}
                            <span class="badge bg-danger ms-1">differs from published logo</span>
                        {/if}
                    </div>
                    <div class="mb-1">
                        <strong>Certified logo hash:</strong>
                        {@render presenceBadge(
                            bimiRecord.vmc.logo_hash_verified,
                            `verified${
                                bimiRecord.vmc.logo_hash_algorithm
                                    ? ` (${bimiRecord.vmc.logo_hash_algorithm})`
                                    : ""
                            }`,
                            "does not cover the embedded logo",
                        )}
                    </div>
                    <div class="mb-1">
                        <strong>Issuer Extended Key Usage:</strong>
                        {@render presenceBadge(bimiRecord.vmc.issuer_has_bimi_eku)}
                        <strong class="ms-3">CRL distribution point:</strong>
                        {@render presenceBadge(bimiRecord.vmc.has_crl_distribution_points)}
                    </div>
                    <div class="mb-1">
                        <strong>Certificate Transparency:</strong>
                        {@render presenceBadge(
                            bimiRecord.vmc.sct_count === undefined
                                ? undefined
                                : bimiRecord.vmc.sct_count > 0,
                            `${bimiRecord.vmc.sct_count} signed timestamp${
                                (bimiRecord.vmc.sct_count ?? 0) > 1 ? "s" : ""
                            }`,
                            "no signed timestamp",
                        )}
                        {#if bimiRecord.vmc.chain_trusted !== undefined}
                            <strong class="ms-3">Issuance chain:</strong>
                            {@render presenceBadge(
                                bimiRecord.vmc.chain_trusted,
                                "leads to a trusted BIMI root",
                                "does not lead to a trusted BIMI root",
                            )}
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
