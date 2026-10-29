<script lang="ts">
    import type {
        BimiCheck,
        BimiCheckMessage,
        BimiRecord,
        Issue,
        VmcInfo,
    } from "#lib/api/types.gen.js";
    import { displayName, inReadingOrder, parseDistinguishedName } from "#lib/certificate.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        bimiRecord?: BimiRecord;
        /** What the analyser found to change about BIMI. */
        issues?: Issue[];
        /** Forces the card open or folded; by default it opens when something is wrong. */
        open?: boolean;
    }

    let { bimiRecord, issues, open }: Props = $props();

    type Status = BimiCheck["status"];

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

    /* How each status is painted, in one place: the checks and the criteria of
       the certificate both read it, so a status cannot end up a different
       colour depending on which of them renders it. */
    const STATUS: Record<Status, { icon: string; label: string; text: string; bg: string }> = {
        pass: {
            icon: "bi-check-circle-fill text-success",
            label: "Passed",
            text: "text-body-secondary",
            bg: "bg-success",
        },
        fail: {
            icon: "bi-x-circle-fill text-danger",
            label: "Failed",
            text: "text-danger-emphasis",
            bg: "bg-danger",
        },
        warning: {
            icon: "bi-exclamation-triangle-fill text-warning",
            label: "Warning",
            text: "text-warning-emphasis",
            bg: "bg-warning",
        },
        skipped: {
            icon: "bi-dash-circle text-body-tertiary",
            label: "Skipped",
            text: "text-body-secondary",
            bg: "bg-secondary",
        },
    };

    const checks = $derived(bimiRecord?.checks ?? []);
    const passed = $derived(checks.filter((c) => c.status === "pass").length);

    /* Optional booleans are left unset when the criterion could not be
       evaluated (e.g. the certificate could not be parsed); that is not the
       same as the criterion being absent, so it never reads as a failure. */
    function triState(value: boolean | undefined): Status {
        if (value === undefined) return "skipped";
        return value ? "pass" : "fail";
    }

    type Criterion = { status: Status; label: string; detail?: string };
    type CriteriaGroup = { title: string; icon: string; criteria: Criterion[] };

    const plural = (n: number, one: string, many: string) => `${n} ${n > 1 ? many : one}`;

    /* What the certificate vouches for, by what it is about: who issued it, the
       mark it carries, and whether its issuance can be audited. */
    function criteriaGroups(vmc: VmcInfo): CriteriaGroup[] {
        const issuance: Criterion[] = [
            {
                status: triState(vmc.has_bimi_eku),
                label: "Issued for BIMI",
                detail: "BIMI Extended Key Usage",
            },
            {
                status: triState(vmc.issuer_has_bimi_eku),
                label: "Issuer allowed to issue mark certificates",
                detail:
                    vmc.issuer_has_bimi_eku === undefined
                        ? "the issuer certificate is not published"
                        : undefined,
            },
        ];
        /* Only an analysis that had a set of trusted roots could reach it: without
           them, a permanently unevaluated criterion would read as one left
           unchecked rather than one never asked. */
        if (vmc.chain_trusted !== undefined) {
            issuance.push({
                status: triState(vmc.chain_trusted),
                label: "Chains to a trusted BIMI root",
            });
        }

        const mark: Criterion[] = [
            {
                status: triState(vmc.has_logotype),
                label: "Logo embedded",
                detail: vmc.logo_media_type,
            },
            {
                status: triState(vmc.logo_hash_verified),
                label: "Logo matches its certified hash",
                detail: vmc.logo_hash_algorithm,
            },
        ];
        // Same: it needs the published logo to compare with.
        if (vmc.logo_matches !== undefined) {
            mark.push({
                status: triState(vmc.logo_matches),
                label: "Same logo as the published one",
                detail: "at the l= URL",
            });
        }

        const audit: Criterion[] = [
            {
                status: triState(vmc.has_crl_distribution_points),
                label: "Revocation can be checked",
                detail: "CRL distribution point",
            },
            {
                status: triState(vmc.sct_count === undefined ? undefined : vmc.sct_count > 0),
                label: "Logged to Certificate Transparency",
                detail:
                    vmc.sct_count === undefined
                        ? undefined
                        : plural(vmc.sct_count, "signed timestamp", "signed timestamps"),
            },
        ];

        return [
            { title: "Issuance", icon: "bi-bank", criteria: issuance },
            { title: "Mark", icon: "bi-image", criteria: mark },
            { title: "Audit", icon: "bi-journal-check", criteria: audit },
        ];
    }

    type Validity = { tone: Status; text: string; elapsed: number };

    const DAY = 24 * 60 * 60 * 1000;

    /* Where today falls in the validity period, and how soon it ends: the
       analyser warns 30 days ahead, so the period reads the same. */
    function validity(vmc: VmcInfo): Validity | undefined {
        if (!vmc.not_before || !vmc.not_after) return undefined;
        const from = new Date(vmc.not_before).getTime();
        const to = new Date(vmc.not_after).getTime();
        const now = Date.now();
        const elapsed = Math.min(1, Math.max(0, (now - from) / (to - from || 1)));

        if (now < from) {
            return { tone: "fail", text: "not yet valid", elapsed };
        }
        if (now > to) {
            const days = Math.floor((now - to) / DAY);
            return {
                tone: "fail",
                text: days > 0 ? `expired ${plural(days, "day", "days")} ago` : "expired today",
                elapsed,
            };
        }
        const days = Math.floor((to - now) / DAY);
        return {
            tone: days < 30 ? "warning" : "pass",
            text: days > 0 ? `expires in ${plural(days, "day", "days")}` : "expires today",
            elapsed,
        };
    }

    function messageColor(message: BimiCheckMessage): string {
        if (message.severity === "info") return "text-body-secondary";
        return message.severity === "warning" ? "text-warning-emphasis" : "text-danger-emphasis";
    }

    function formatDate(date: string): string {
        return new Date(date).toLocaleDateString();
    }
</script>

<!-- The certificate the a= tag points to, read as a card would be: who it is
     issued to and by, for how long, for which domains, then what it vouches for. -->
{#snippet certificate(vmc: VmcInfo)}
    {@const subject = parseDistinguishedName(vmc.subject ?? "")}
    {@const issuer = parseDistinguishedName(vmc.issuer ?? "")}
    {@const period = validity(vmc)}
    <div class="d-flex flex-column gap-3 mt-2 p-3 bg-body-tertiary border rounded">
        <div class="d-flex align-items-center gap-3">
            <i class="bi bi-patch-check fs-3 text-body-tertiary" aria-hidden="true"></i>
            <div class="text-break">
                <div class="fw-semibold" title={vmc.subject}>
                    {displayName(subject) ?? vmc.subject}
                </div>
                {#if vmc.issuer}
                    <div class="small text-body-secondary" title={vmc.issuer}>
                        issued by {displayName(issuer) ?? vmc.issuer}
                    </div>
                {/if}
            </div>
        </div>

        {#if period && vmc.not_before && vmc.not_after}
            <div>
                <div class="d-flex flex-wrap justify-content-between column-gap-3 small">
                    <span>
                        {formatDate(vmc.not_before)} &rarr; {formatDate(vmc.not_after)}
                    </span>
                    <span class={STATUS[period.tone].text}>{period.text}</span>
                </div>
                <div
                    class="progress mt-1"
                    style:--bs-progress-height="0.25rem"
                    style:--bs-progress-bg="var(--bs-border-color)"
                    role="progressbar"
                    aria-label="Validity period elapsed"
                    aria-valuenow={Math.round(period.elapsed * 100)}
                    aria-valuemin={0}
                    aria-valuemax={100}
                >
                    <div
                        class="progress-bar {STATUS[period.tone].bg}"
                        style:width="{period.elapsed * 100}%"
                    ></div>
                </div>
            </div>
        {/if}

        {#if vmc.san_domains && vmc.san_domains.length > 0}
            <div class="small">
                <span class="text-body-secondary me-1">Covers</span>
                {#each vmc.san_domains as san (san)}
                    <span
                        class="d-inline-block me-1 mb-1 px-1 font-monospace bg-body border rounded-1"
                        >{san}</span
                    >
                {/each}
            </div>
        {/if}

        <!-- The three groups side by side where there is room, one under another where not. -->
        <div class="row row-cols-1 row-cols-md-3 g-3">
            {#each criteriaGroups(vmc) as group (group.title)}
                <section class="col">
                    <h6 class="small text-uppercase text-body-secondary mb-1">
                        <i class="bi {group.icon} me-1" aria-hidden="true"></i>{group.title}
                    </h6>
                    <ul class="list-unstyled vstack gap-1 mb-0">
                        {#each group.criteria as criterion (criterion.label)}
                            <li class="d-flex gap-2">
                                <i
                                    class="bi {STATUS[criterion.status].icon}"
                                    role="img"
                                    aria-label={criterion.status === "skipped"
                                        ? "Not evaluated"
                                        : STATUS[criterion.status].label}
                                    title={criterion.status === "skipped"
                                        ? "Not evaluated"
                                        : STATUS[criterion.status].label}
                                ></i>
                                <span>
                                    {criterion.label}
                                    {#if criterion.detail}
                                        <span class="d-block small text-body-secondary"
                                            >{criterion.detail}</span
                                        >
                                    {/if}
                                </span>
                            </li>
                        {/each}
                    </ul>
                </section>
            {/each}
        </div>

        <details class="passed-items">
            <summary>Certificate details</summary>
            <dl class="check-facts bg-body mt-2 mb-0">
                {#each inReadingOrder(subject) as attribute, i (i)}
                    <dt>{attribute.label}</dt>
                    <dd>{attribute.value}</dd>
                {/each}
                {#if issuer.length > 0}
                    <dt>Issuer</dt>
                    <dd title={vmc.issuer}>{issuer.map((a) => a.value).join(", ")}</dd>
                {/if}
                {#if vmc.serial_number}
                    <dt>Serial number</dt>
                    <dd class="font-monospace small">{vmc.serial_number}</dd>
                {/if}
                {#if vmc.chain_length !== undefined}
                    <dt>Chain</dt>
                    <dd>{plural(vmc.chain_length, "certificate", "certificates")} published</dd>
                {/if}
            </dl>
        </details>
    </div>
{/snippet}

{#if bimiRecord}
    <!-- BIMI is optional: a domain without a record has nothing broken, only something
         it could add, so the card does not open itself for that. -->
    <CheckCard
        id="dns-bimi"
        title="Brand Indicators for Message Identification"
        tag="BIMI"
        status={!bimiRecord.record
            ? "neutral"
            : bimiRecord.record_valid === false || !bimiRecord.valid
              ? "fail"
              : "pass"}
        summary={bimiRecord.record ?? bimiRecord.error ?? "No BIMI record (optional)"}
        summaryFoldedOnly={!!bimiRecord.record}
        docs={[docs.bimi, docs.bimiGroup]}
        {issues}
        {open}
    >
        <div class="card-body">
            <dl class="check-facts">
                <dt>Queried</dt>
                <dd>
                    <span class="font-monospace"
                        >{bimiRecord.selector}._bimi.{bimiRecord.domain}</span
                    >
                </dd>
                {#if inheritedFrom}
                    <dt>Found at</dt>
                    <dd>
                        <span class="font-monospace"
                            >{bimiRecord.selector}._bimi.{inheritedFrom}</span
                        >
                        <div class="small text-body-secondary">
                            {bimiRecord.domain} has no record of its own: this one is inherited from its
                            organizational domain. Publish one, or a declination record, to give it its
                            own.
                        </div>
                    </dd>
                {/if}
                {#if derivedFromLocalPart}
                    <dt>Selector</dt>
                    <dd>
                        <code>{bimiRecord.selector}</code>
                        <div class="small text-body-secondary">
                            The record at <code>{bimiRecord.requested_selector}</code> sends this sender
                            to a selector named after its address (lps=).
                        </div>
                    </dd>
                {:else if localPartScope}
                    <dt>Senders</dt>
                    <dd class="small text-body-secondary">
                        lps= sends {localPartScope} to a selector named after the address, which can serve
                        them another indicator.
                    </dd>
                {/if}
                {#if bimiRecord.record}
                    <dt>Record</dt>
                    <dd>
                        <code>{bimiRecord.record}</code>
                        {#if bimiRecord.record_valid === false && bimiRecord.error}
                            <div class="small text-danger">{bimiRecord.error}</div>
                        {/if}
                    </dd>
                {:else if bimiRecord.error}
                    <dt>Record</dt>
                    <dd>{bimiRecord.error}</dd>
                {/if}
                {#if bimiRecord.avatar_preference}
                    <dt>Avatar preference</dt>
                    <dd>
                        <code>{bimiRecord.avatar_preference}</code>
                        <span class="small text-body-secondary">
                            {#if bimiRecord.avatar_preference === "personal"}
                                , the sender's own avatar is preferred over the brand indicator
                            {:else if bimiRecord.avatar_preference === "brand"}
                                , the brand indicator is preferred (the default)
                            {:else}
                                , unknown value: receivers fall back to <code>brand</code>
                            {/if}
                        </span>
                    </dd>
                {/if}
                {#if bimiRecord.logo_url}
                    <dt>Logo</dt>
                    <dd>
                        <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- external URL, not a SvelteKit route -->
                        <a href={bimiRecord.logo_url} target="_blank" rel="noopener noreferrer"
                            >{bimiRecord.logo_url}</a
                        >
                    </dd>
                {/if}
                {#if bimiRecord.vmc_url}
                    <dt>Certificate</dt>
                    <dd>
                        <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- external URL, not a SvelteKit route -->
                        <a href={bimiRecord.vmc_url} target="_blank" rel="noopener noreferrer"
                            >{bimiRecord.vmc_url}</a
                        >
                    </dd>
                {/if}
            </dl>

            {#if checks.length > 0}
                <!-- Every check in sight, each with its verdict: what BIMI asks of the
                     record, the logo and the certificate is the substance of the card. -->
                <h6 class="small text-uppercase text-body-secondary mb-1">
                    Checks
                    <span class="text-lowercase">({passed} of {checks.length} passed)</span>
                </h6>
                <ul class="list-group list-group-flush">
                    {#each checks as check (check.name)}
                        <li class="list-group-item d-flex gap-2 px-0 bg-transparent">
                            <i
                                class="bi {STATUS[check.status].icon}"
                                role="img"
                                aria-label={STATUS[check.status].label}
                                title={STATUS[check.status].label}
                            ></i>
                            <div class="flex-grow-1 text-break">
                                <div class="d-flex flex-wrap column-gap-2 align-items-baseline">
                                    <span
                                        class={check.status === "skipped"
                                            ? "text-body-secondary"
                                            : "fw-semibold"}>{check.description}</span
                                    >
                                    <span class="small {STATUS[check.status].text}">
                                        {STATUS[check.status].label}
                                    </span>
                                </div>
                                {#if check.messages && check.messages.length > 0}
                                    <ul class="small mb-0 ps-3">
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
                                <!-- The certificate is what this check examined: it is shown
                                     where its verdict is, unless it could not even be read,
                                     which the messages above say. -->
                                {#if check.name === "vmc" && bimiRecord.vmc?.subject}
                                    {@render certificate(bimiRecord.vmc)}
                                {/if}
                            </div>
                        </li>
                    {/each}
                </ul>
            {/if}

            <p class="check-about">
                BIMI lets supporting mailboxes display your brand logo next to your messages. It
                requires an enforced DMARC policy, and most providers also a mark certificate (VMC
                or CMC) vouching for the logo.
            </p>
        </div>
    </CheckCard>
{/if}
