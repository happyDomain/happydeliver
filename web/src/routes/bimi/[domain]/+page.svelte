<script lang="ts">
    import { page } from "$app/state";
    import { resolve } from "$app/paths";

    import { checkBimi } from "$lib/api";
    import type { BimiCheckResponse } from "$lib/api/types.gen";
    import { BimiRecordDisplay, DmarcRecordDisplay, TinySurvey } from "$lib/components";

    let domain = $derived(page.params.domain ?? "");
    let selector = $derived(page.url.searchParams.get("selector") || "default");
    let localPart = $derived(page.url.searchParams.get("local_part") || "");

    let loading = $state(true);
    let error = $state<string | null>(null);
    let result = $state<BimiCheckResponse | null>(null);

    async function runCheck(target: string, sel: string, lp: string) {
        loading = true;
        error = null;
        result = null;

        if (!target) {
            error = "Domain parameter is missing";
            loading = false;
            return;
        }

        try {
            const response = await checkBimi({
                body: {
                    domain: target,
                    selector: sel,
                    ...(lp ? { local_part: lp } : {}),
                },
            });

            if (response.data) {
                result = response.data;
            } else if (response.error) {
                error = response.error.message || "Failed to check the BIMI record";
            }
        } catch (err) {
            error = err instanceof Error ? err.message : "Failed to check the BIMI record";
        } finally {
            loading = false;
        }
    }

    /* Re-runs when the address bar changes, so editing the selector in the URL
       or coming back through history checks what is actually being asked for
       rather than replaying the first lookup. */
    $effect(() => {
        runCheck(domain, selector, localPart);
    });

    const record = $derived(result?.bimi_record);

    /* Whether section 7.1 forbids BIMI processing here, read off the check the
       analyser produced rather than recomputed from the DMARC policy, so this
       page cannot disagree with the card below it. */
    const dmarcBlocked = $derived(
        record?.checks?.some((c) => c.name === "dmarc_enforcement" && c.status === "fail") ?? false,
    );

    /* A record that publishes no a= tag asserts its Indicator on the Domain
       Owner's word alone. The tag is optional, so the record stays valid, but
       the verdict cannot call that "compliant" when the providers most people
       read their mail on will show nothing. Read off the check rather than
       from vmc_url alone: a published certificate can warn for its own
       reasons, and only the analyser knows which case this is. */
    const selfAsserted = $derived(
        !record?.vmc_url &&
            (record?.checks?.some((c) => c.name === "vmc" && c.status === "warning") ?? false),
    );

    /* Both asset tags left empty: a Declination to Publish, which is a
       deliberate and correct configuration rather than a half-finished one. */
    const declination = $derived(!!record?.record_valid && !record?.logo_url && !record?.vmc_url);

    type Verdict = {
        level: "success" | "warning" | "danger" | "secondary";
        icon: string;
        title: string;
        text: string;
    };

    const verdict: Verdict | undefined = $derived.by(() => {
        if (!record) return undefined;

        if (!record.record) {
            return {
                level: "danger",
                icon: "bi-x-octagon-fill",
                title: "No BIMI record published",
                text: `Nothing is published at ${record.selector}._bimi.${record.domain}, so no mail client will show an indicator for this domain.`,
            };
        }
        if (!record.record_valid) {
            return {
                level: "danger",
                icon: "bi-x-octagon-fill",
                title: "The Assertion Record is not valid",
                text: "The TXT record was found but it is not a well-formed BIMI record, so receivers cannot act on it.",
            };
        }
        if (dmarcBlocked) {
            return {
                level: "danger",
                icon: "bi-exclamation-octagon-fill",
                title: "This indicator will not be displayed",
                text: "A message only becomes eligible for BIMI once the sending domain's DMARC policy is at enforcement. Until then, nothing is shown however compliant the record and the logo are.",
            };
        }
        if (!record.valid) {
            return {
                level: "danger",
                icon: "bi-exclamation-octagon-fill",
                title: "The record is valid, its assets are not",
                text: "The DNS record is well-formed, but the logo or the certificate it points at failed validation. An indicator receivers cannot validate is one they do not display, so nothing will be shown until this is fixed. Expand the detailed checks below to see what failed.",
            };
        }
        if (declination) {
            return {
                level: "secondary",
                icon: "bi-slash-circle-fill",
                title: "This domain declines to publish an indicator",
                text: "The record is well-formed and publishes neither a logo nor a certificate, which is how a domain deliberately opts out of BIMI. No indicator will be shown, and none is meant to be.",
            };
        }
        if (selfAsserted) {
            return {
                level: "warning",
                icon: "bi-patch-exclamation-fill",
                title: "Valid, but the indicator is self-asserted",
                text: "The record and the logo passed, and the a= tag they leave out is optional. But with no Verified Mark Certificate vouching for the logo, only the mail clients that accept a self-asserted indicator will display it: Gmail and Apple Mail, between them most of the inboxes, will not.",
            };
        }
        return {
            level: "success",
            icon: "bi-check-circle-fill",
            title: "This BIMI configuration is compliant",
            text: "The record, the logo and the certificate all passed. Mail clients that support BIMI can display this indicator for messages that pass DMARC.",
        };
    });
</script>

<svelte:head>
    <title>{domain} - BIMI Checker - happyDeliver</title>
</svelte:head>

<div class="container py-5">
    <div class="row">
        <div class="col-lg-10 mx-auto">
            <!-- Header -->
            <div class="mb-4">
                <div class="d-flex align-items-center justify-content-between">
                    <h1 class="h2 mb-0">
                        <i class="bi bi-building-check me-2"></i>
                        BIMI Check
                    </h1>
                    <a href={resolve("/bimi")} class="btn btn-outline-secondary">
                        <i class="bi bi-arrow-left me-2"></i>
                        Check Another Domain
                    </a>
                </div>
            </div>

            {#if loading}
                <!-- Loading State -->
                <div class="card shadow-sm">
                    <div class="card-body text-center py-5">
                        <div class="spinner-border text-primary mb-3" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        <h3 class="h5">Checking {domain}...</h3>
                        <p class="text-muted mb-0">
                            Reading the record, then fetching the logo and the certificate it points
                            at. This can take a few seconds.
                        </p>
                    </div>
                </div>
            {:else if error}
                <!-- Error State -->
                <div class="card shadow-sm">
                    <div class="card-body text-center py-5">
                        <i class="bi bi-exclamation-triangle text-danger" style="font-size: 4rem;"
                        ></i>
                        <h3 class="h4 mt-4">Check Failed</h3>
                        <p class="text-muted mb-4">{error}</p>
                        <button
                            class="btn btn-primary"
                            onclick={() => runCheck(domain, selector, localPart)}
                        >
                            <i class="bi bi-arrow-clockwise me-2"></i>
                            Try Again
                        </button>
                    </div>
                </div>
            {:else if result && record}
                <!-- Results -->
                <div class="fade-in">
                    <!-- Verdict -->
                    <div class="card shadow-sm mb-4 border-{verdict?.level}">
                        <div class="card-body p-4">
                            <div class="d-flex align-items-start gap-3">
                                <i
                                    class="bi {verdict?.icon} text-{verdict?.level}"
                                    style="font-size: 2.5rem; line-height: 1;"
                                ></i>
                                <div class="flex-grow-1">
                                    <h2 class="h4 mb-1">{verdict?.title}</h2>
                                    <p class="text-muted mb-0">{verdict?.text}</p>
                                </div>
                            </div>
                            <hr />
                            <div class="small">
                                <strong>Queried:</strong>
                                <code>{result.selector}._bimi.{result.domain}</code>
                                {#if result.local_part}
                                    <span class="ms-3">
                                        <strong>As sender:</strong>
                                        <code>{result.local_part}@{result.domain}</code>
                                    </span>
                                {/if}
                            </div>
                            <div class="d-flex justify-content-end mt-3">
                                <TinySurvey
                                    class="bg-primary-subtle rounded-4 p-3 text-center"
                                    source={"bimi-" + result.domain}
                                />
                            </div>
                        </div>
                    </div>

                    <!-- BIMI Record -->
                    <BimiRecordDisplay bimiRecord={record} dmarcRecord={result.dmarc_record} />

                    <!-- DMARC Record: BIMI display hangs on it, and the card
                         above links here to explain a blocked indicator. -->
                    <DmarcRecordDisplay
                        dmarcRecord={result.dmarc_record}
                        fromDomain={result.domain}
                    />

                    <!-- Next Steps -->
                    <div class="card shadow-sm border-primary mt-4">
                        <div class="card-body">
                            <h3 class="h5 mb-3">
                                <i class="bi bi-lightbulb me-2"></i>
                                Want the Whole Picture?
                            </h3>
                            <p class="mb-3">
                                This check looks at the BIMI record alone. A domain also needs SPF,
                                DKIM and a healthy reputation for its messages to reach the inbox
                                the indicator would appear in:
                            </p>
                            <a
                                href={resolve("/domain/[domain]", { domain: result.domain })}
                                class="btn btn-primary me-2"
                            >
                                <i class="bi bi-globe me-2"></i>
                                Check the Domain's DNS
                            </a>
                            <a href={resolve("/")} class="btn btn-outline-primary">
                                <i class="bi bi-envelope-plus me-2"></i>
                                Send a Test Email
                            </a>
                        </div>
                    </div>
                </div>
            {/if}
        </div>
    </div>
</div>

<style>
    .fade-in {
        animation: fadeIn 0.5s ease-out;
    }

    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(15px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
</style>
