<script lang="ts">
    import type {
        AuthenticationIssues,
        AuthenticationResults,
        DnsResults,
        Issue,
    } from "#lib/api/types.gen.js";
    import {
        hasNoAuthenticationResults,
        isUploadedMessage,
        verdictStatus,
        type MessageSource,
    } from "#lib/authentication.js";
    import { docs } from "#lib/docs.js";
    import { listed } from "#lib/issues.js";
    import type { SectionStatus } from "#lib/sections.js";
    import CheckCard from "./CheckCard.svelte";
    import CheckList from "./CheckList.svelte";
    import IssueNote from "./IssueNote.svelte";
    import ReportSection from "./ReportSection.svelte";

    interface Props {
        authentication: AuthenticationResults;
        authenticationGrade?: string;
        authenticationScore?: number;
        dnsResults?: DnsResults;
        source?: MessageSource;
        authservId?: string;
        status?: SectionStatus;
        open?: boolean;
    }

    let {
        authentication,
        authenticationGrade,
        authenticationScore,
        dnsResults,
        source,
        authservId,
        status,
        open = true,
    }: Props = $props();

    let allRequiredMissing = $derived(hasNoAuthenticationResults(authentication));
    let uploaded = $derived(isUploadedMessage(source));

    /**
     * The issues of a check, or nothing when it has none: its verdict then says how it
     * came out, as not every verdict the receiver reports calls for a change.
     */
    function at(check: keyof AuthenticationIssues): Issue[] | undefined {
        return listed(authentication.issues?.[check]);
    }

    /** The verdict, with the domain it is about when there is one. */
    function verdict(result: string | undefined, domain?: string): string {
        if (!result || result === "missing") return "Not tested";
        return domain ? `${result} for ${domain}` : result;
    }

    // One passing signature is all DMARC needs: the others only matter for their findings.
    const dkim = $derived(authentication.dkim ?? []);
    const dkimResult = $derived(dkim.find((d) => d.result === "pass")?.result ?? dkim[0]?.result);
    const dkimSummary = $derived(
        dkim.length > 1
            ? `${dkim.filter((d) => d.result === "pass").length} of ${dkim.length} signatures pass`
            : verdict(dkim[0]?.result, dkim[0]?.domain),
    );

    // The policy the receiver applied, or failing that the one the domain publishes
    const dmarcPolicy = $derived.by(() => {
        const dmarc = authentication.dmarc;
        if (!dmarc || dmarc.result === "none") return undefined;
        const applied = dmarc.details?.match(/policy\.published-domain-policy=([^\s;]+)/)?.[1];
        return applied ?? (dmarc.domain ? dnsResults?.dmarc_record?.policy : undefined);
    });

    const serverSubject = $derived(
        authentication.x_ptr?.helo ?? authentication.iprev?.hostname ?? authentication.iprev?.ip,
    );
</script>

<!-- The receiver's raw verdict: needed to debug a failure, noise on a pass. -->
{#snippet rawResult(details: string | undefined)}
    {#if details}
        <details class="passed-items mt-1">
            <summary>Raw result</summary>
            <pre
                class="p-2 mb-0 mt-1 text-muted small"
                style="white-space: pre-wrap">{details}</pre>
        </details>
    {/if}
{/snippet}

<!-- No Authentication-Results header: the score is not the sender's, so it shows as N/A. -->
<ReportSection
    id="authentication-details"
    title="Authentication"
    icon="shield-check"
    grade={authenticationGrade}
    score={authenticationScore}
    unavailable={allRequiredMissing}
    {status}
    {open}
>
    <div class="card-body">
        {#each authentication.issues?.details ?? [] as issue, i (i)}
            <IssueNote {issue} />
        {/each}

        {#if uploaded && !allRequiredMissing}
            <!-- Not this instance's verdicts: the reader has to know whose they are. -->
            <p class="small text-body-secondary">
                <i class="bi bi-info-circle me-1" aria-hidden="true"></i>
                These verdicts were produced by
                {#if authservId}
                    <code>{authservId}</code>, the server
                {:else}
                    the server of your mail provider
                {/if}
                that received the uploaded message, not by this instance.
            </p>
        {/if}

        {#if authentication.iprev || authentication.x_ptr || authentication.x_tls || authentication.spf_helo}
            <CheckList title="Sending server" subject={serverSubject}>
                {#if authentication.iprev}
                    {@const iprev = authentication.iprev}
                    <CheckCard
                        id="authentication-iprev"
                        title="Reverse DNS"
                        tag="iprev"
                        status={verdictStatus(iprev.result, true)}
                        summary={verdict(iprev.result, iprev.ip)}
                        docs={[docs.reverseDns]}
                        issues={at("iprev")}
                    >
                        <div class="card-body">
                            <dl class="check-facts">
                                {#if iprev.ip}
                                    <dt>IP address</dt>
                                    <dd><code>{iprev.ip}</code></dd>
                                {/if}
                                {#if iprev.hostname}
                                    <dt>Hostname</dt>
                                    <dd><code>{iprev.hostname}</code></dd>
                                {/if}
                            </dl>
                            <p class="check-about">
                                Receivers look up the name of the sending IP, and check that this
                                name resolves back to the same IP: a server without it looks like a
                                compromised home connection.
                            </p>
                            {@render rawResult(iprev.details)}
                        </div>
                    </CheckCard>
                {/if}

                {#if authentication.x_ptr}
                    {@const xptr = authentication.x_ptr}
                    <CheckCard
                        id="authentication-x-ptr"
                        title="HELO hostname"
                        tag="HELO / PTR"
                        status={verdictStatus(xptr.result, false)}
                        summary={xptr.result === "fail" && xptr.helo && xptr.ptr
                            ? `${xptr.helo}, not ${xptr.ptr}`
                            : verdict(xptr.result, xptr.helo)}
                        docs={[docs.ehlo]}
                    >
                        <div class="card-body">
                            <dl class="check-facts">
                                {#if xptr.helo}
                                    <dt>Announced</dt>
                                    <dd><code>{xptr.helo}</code></dd>
                                {/if}
                                {#if xptr.ptr}
                                    <dt>Reverse DNS</dt>
                                    <dd><code>{xptr.ptr}</code></dd>
                                {/if}
                            </dl>
                            <p class="check-about">
                                When it connects, the sending server announces its hostname (HELO or
                                EHLO). Many receivers check that it is the name its IP has in
                                reverse DNS; a mismatch is a common spam signal.
                            </p>
                            {@render rawResult(xptr.details)}
                        </div>
                    </CheckCard>
                {/if}

                {#if authentication.spf_helo}
                    {@const helo = authentication.spf_helo}
                    <CheckCard
                        id="authentication-spf-helo"
                        title="SPF of the HELO hostname"
                        tag="SPF"
                        status={verdictStatus(helo.result, false)}
                        summary={verdict(helo.result, helo.domain)}
                        docs={[docs.spfHelo]}
                        issues={at("spf_helo")}
                    >
                        <div class="card-body">
                            <p class="check-about">
                                The same check as SPF, on the hostname the sending server announced
                                rather than on the envelope sender: it covers the bounces, which
                                have no envelope sender.
                            </p>
                            {@render rawResult(helo.details)}
                        </div>
                    </CheckCard>
                {/if}

                {#if authentication.x_tls}
                    {@const tls = authentication.x_tls}
                    <CheckCard
                        id="authentication-x-tls"
                        title="Transport encryption"
                        tag="TLS"
                        status={verdictStatus(tls.result, true)}
                        summary={tls.details ?? verdict(tls.result)}
                        docs={[docs.starttls]}
                        issues={at("x_tls")}
                    >
                        <div class="card-body">
                            <p class="check-about">
                                Whether the connection that delivered this message to the receiver
                                was encrypted (STARTTLS), so that nobody along the way could read
                                it.
                            </p>
                        </div>
                    </CheckCard>
                {/if}
            </CheckList>
        {/if}

        <!-- Each verdict names the domain it is about: SPF the envelope sender's, DKIM the
             signer's, DMARC and BIMI the From domain's. -->
        <CheckList title="Sender identity">
            <CheckCard
                id="authentication-spf"
                title="Sender Policy Framework"
                tag="SPF"
                status={authentication.spf
                    ? verdictStatus(authentication.spf.result, true)
                    : authentication.spf_helo
                      ? "neutral"
                      : "fail"}
                summary={authentication.spf
                    ? verdict(authentication.spf.result, authentication.spf.domain)
                    : authentication.spf_helo
                      ? "Not checked for the envelope sender"
                      : "Not tested"}
                docs={[docs.spf]}
                issues={at("spf")}
            >
                <div class="card-body">
                    {#if !authentication.spf && authentication.spf_helo}
                        <p class="check-about">
                            The receiver only checked the HELO identity, so it reported no verdict
                            for the envelope sender.
                        </p>
                    {:else}
                        <p class="check-about">
                            The receiver checked that the sending IP is one the SPF record of the
                            envelope sender domain (the Return-Path, where bounces go) allows.
                        </p>
                    {/if}
                    {@render rawResult(authentication.spf?.details)}
                </div>
            </CheckCard>

            <CheckCard
                id="authentication-dkim"
                title="DomainKeys Identified Mail"
                tag="DKIM"
                status={verdictStatus(dkimResult, true)}
                summary={dkimSummary}
                docs={[docs.dkim]}
                issues={at("dkim")}
            >
                <div class="card-body">
                    {#if dkim.length > 0}
                        <dl class="check-facts">
                            {#each dkim as signature, i (i)}
                                <dt>
                                    {signature.domain ?? "Signature"}
                                    {#if signature.selector}
                                        <span class="d-block small">{signature.selector}</span>
                                    {/if}
                                </dt>
                                <dd>
                                    <span
                                        class={verdictStatus(signature.result, true) === "pass"
                                            ? "text-success"
                                            : "text-danger"}>{signature.result}</span
                                    >
                                    {@render rawResult(signature.details)}
                                </dd>
                            {/each}
                        </dl>
                    {/if}
                    <p class="check-about">
                        The receiver checked each signature against the public key its domain
                        publishes in DNS.
                    </p>
                </div>
            </CheckCard>

            <CheckCard
                id="authentication-dmarc"
                title="Domain-based Message Authentication"
                tag="DMARC"
                status={verdictStatus(authentication.dmarc?.result, true)}
                summary={verdict(authentication.dmarc?.result, authentication.dmarc?.domain)}
                docs={[docs.dmarc]}
                issues={at("dmarc")}
            >
                <div class="card-body">
                    {#if dmarcPolicy}
                        <dl class="check-facts">
                            <dt>Policy</dt>
                            <dd><code>{dmarcPolicy}</code></dd>
                        </dl>
                    {/if}
                    <p class="check-about">
                        DMARC passes when SPF or DKIM passes for a domain aligned with the From
                        address, the one the recipient sees. Otherwise the receiver applies the
                        policy the From domain publishes.
                    </p>
                    {@render rawResult(authentication.dmarc?.details)}
                </div>
            </CheckCard>

            {#if authentication.x_aligned_from}
                {@const aligned = authentication.x_aligned_from}
                <CheckCard
                    id="authentication-x-aligned-from"
                    title="Aligned From"
                    tag="X-Aligned-From"
                    status={verdictStatus(aligned.result, false)}
                    summary={verdict(aligned.result, aligned.domain)}
                    docs={[docs.dmarcAlignment]}
                    issues={at("x_aligned_from")}
                >
                    <div class="card-body">
                        <p class="check-about">
                            Whether the envelope sender and the From address are in the same domain.
                            See <a href="#domain-alignment">Domain Alignment</a>.
                        </p>
                        {@render rawResult(aligned.details)}
                    </div>
                </CheckCard>
            {/if}

            <CheckCard
                id="authentication-bimi"
                title="Brand Indicators"
                tag="BIMI"
                status={verdictStatus(authentication.bimi?.result, false)}
                summary={authentication.bimi ? verdict(authentication.bimi.result) : "Optional"}
                docs={[docs.bimi]}
                issues={at("bimi")}
            >
                <div class="card-body">
                    <p class="check-about">
                        Whether the receiver would display your brand logo next to the message. The
                        record and the logo are checked with the <a href="#dns-bimi">DNS records</a
                        >.
                    </p>
                    {@render rawResult(authentication.bimi?.details)}
                </div>
            </CheckCard>
        </CheckList>

        <!-- What happened between the sender and the receiver: Google seals what it routes,
             a list or a forwarder seals what it passes on. Not the sender domain's doing. -->
        {#if authentication.x_google_dkim || authentication.arc}
            <CheckList title="In transit">
                {#if authentication.x_google_dkim}
                    {@const google = authentication.x_google_dkim}
                    <CheckCard
                        id="authentication-x-google-dkim"
                        title="Google's internal signature"
                        tag="X-Google-DKIM"
                        status={verdictStatus(google.result, false)}
                        summary={verdict(google.result, google.domain)}
                        docs={[docs.dkim]}
                        issues={at("x_google_dkim")}
                    >
                        <div class="card-body">
                            <p class="check-about">
                                Google signs the messages it routes; a signature that no longer
                                verifies means something changed the message afterwards.
                            </p>
                            {@render rawResult(google.details)}
                        </div>
                    </CheckCard>
                {/if}

                {#if authentication.arc}
                    {@const arc = authentication.arc}
                    <CheckCard
                        id="authentication-arc"
                        title="Authenticated Received Chain"
                        tag="ARC"
                        status={verdictStatus(arc.result, false)}
                        summary={arc.chain_length
                            ? `${arc.result}, chain of ${arc.chain_length}`
                            : verdict(arc.result)}
                        docs={[docs.arc]}
                        issues={at("arc")}
                    >
                        <div class="card-body">
                            <p class="check-about">
                                The seals of the intermediaries that forwarded the message, vouching
                                for the authentication results it had when they received it.
                            </p>
                            {@render rawResult(arc.details)}
                        </div>
                    </CheckCard>
                {/if}
            </CheckList>
        {/if}
    </div>
</ReportSection>
