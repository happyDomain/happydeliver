<script lang="ts">
    import type {
        AuthenticationIssues,
        AuthenticationResults,
        DnsResults,
        DomainAlignment,
        Issue,
        ReceivedHop,
        SpfRecord,
    } from "#lib/api/types.gen.js";
    import {
        hasNoAuthenticationResults,
        isAlignedWith,
        isUploadedMessage,
        parseVerdictDetails,
        rawVerdict,
        sameDomain,
        verdictMeaning,
        verdictStatus,
        type MessageSource,
        type VerdictMechanism,
    } from "#lib/authentication.js";
    import { docs } from "#lib/docs.js";
    import { listed } from "#lib/issues.js";
    import type { SectionStatus } from "#lib/sections.js";
    import CheckCard, { statusTones } from "./CheckCard.svelte";
    import CheckList from "./CheckList.svelte";
    import FactRow from "./FactRow.svelte";
    import IssueNote from "./IssueNote.svelte";
    import ReportSection from "./ReportSection.svelte";
    import VerdictFacts from "./VerdictFacts.svelte";

    interface Props {
        authentication: AuthenticationResults;
        authenticationGrade?: string;
        authenticationScore?: number;
        dnsResults?: DnsResults;
        /** The domains of the message, to tell which verdicts are about the From domain. */
        alignment?: DomainAlignment;
        /** The hop the message entered the receiver through, which an x-tls verdict may rest on. */
        inboundHop?: ReceivedHop;
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
        alignment,
        inboundHop,
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

    const senderIp = $derived(authentication.iprev?.ip ?? dnsResults?.sender_ip);
    const fromDomain = $derived(alignment?.from_domain ?? dnsResults?.from_domain);
    const envelopeDomain = $derived(alignment?.return_path_domain ?? dnsResults?.rp_domain);
    const dmarcRecord = $derived(dnsResults?.dmarc_record);

    // One passing signature is all DMARC needs: the others only matter for their findings.
    const dkim = $derived(authentication.dkim ?? []);
    const dkimResult = $derived(dkim.find((d) => d.result === "pass")?.result ?? dkim[0]?.result);
    const dkimSummary = $derived(
        dkim.length > 1
            ? `${dkim.filter((d) => d.result === "pass").length} of ${dkim.length} signatures pass`
            : verdict(dkim[0]?.result, dkim[0]?.domain),
    );

    const serverSubject = $derived(
        authentication.x_ptr?.helo ?? authentication.iprev?.hostname ?? authentication.iprev?.ip,
    );

    // The DNS lookups of this instance only tell about the IP the receiver checked when it
    // is the same one: an uploaded message may have been checked on another hop.
    const sameIp = $derived(
        !!dnsResults?.sender_ip && dnsResults.sender_ip === authentication.iprev?.ip,
    );

    // The parameters of the connection: those the receiver wrote with its x-tls verdict, or,
    // when the analyser read the verdict off the inbound hop, those of that hop.
    const tls = $derived.by(() => {
        const xtls = authentication.x_tls;
        if (!xtls) return undefined;
        if (xtls.details) {
            const props = parseVerdictDetails(xtls.details).properties;
            return {
                version: props["smtp.version"],
                cipher: props["smtp.cipher"],
                bits: props["smtp.bits"],
                verified: undefined,
                transport: undefined,
                fromHop: false,
            };
        }
        if (!inboundHop) return undefined;
        return {
            version: inboundHop.tls?.version,
            cipher: inboundHop.tls?.cipher,
            bits: inboundHop.tls?.bits?.toString(),
            verified: inboundHop.tls?.verified,
            transport: inboundHop.with,
            fromHop: true,
        };
    });

    // The SPF record the receiver evaluated, when this instance fetched the same one.
    function spfRecordOf(domain: string | undefined, records = dnsResults?.spf_records) {
        if (!domain) return undefined;
        return records?.find((r) => sameDomain(r.domain, domain));
    }

    // The public key a signature points at, when this instance fetched it.
    function dkimRecordOf(domain: string | undefined, selector: string | undefined) {
        if (!domain || !selector) return undefined;
        return dnsResults?.dkim_records?.find(
            (r) => sameDomain(r.domain, domain) && r.selector === selector,
        );
    }

    const allQualifiers: Record<string, string> = {
        "-": "fail (-all)",
        "~": "softfail (~all)",
        "?": "neutral (?all)",
        "+": "pass (+all)",
    };
</script>

<!-- The verdict, and what it means. -->
{#snippet verdictRow(mechanism: VerdictMechanism, result: string | undefined, required = true)}
    {@const meaning = verdictMeaning(mechanism, result)}
    <FactRow label="Verdict">
        <span class="fw-semibold {statusTones[verdictStatus(result, required)]}"
            >{result ?? "not reported"}</span
        >
        {#if meaning}
            <span class="fact-note">{meaning}</span>
        {/if}
    </FactRow>
{/snippet}

<!-- What the receiver wrote in parentheses: its own explanation, often the clearest one. -->
{#snippet receiverNote(details: string | undefined)}
    {@const comments = parseVerdictDetails(details).comments}
    {#if comments.length > 0}
        <FactRow label="Receiver's note">
            {#each comments as comment, i (i)}
                <span class="d-block">{comment}</span>
            {/each}
        </FactRow>
    {/if}
{/snippet}

<!-- An SPF record this instance fetched, and what it does with the IPs it does not list. -->
{#snippet spfRecordRow(label: string, record: SpfRecord | undefined)}
    {#if record?.record}
        <FactRow {label}>
            <code>{record.record}</code>
            {#if record.all_qualifier}
                <span class="fact-note"
                    >Any IP it does not list: {allQualifiers[record.all_qualifier]}.</span
                >
            {/if}
        </FactRow>
    {:else if record}
        <FactRow {label} value="none published" />
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
                    <span class="font-monospace">{authservId}</span>, the server
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
                    {@const ptrs = sameIp ? dnsResults?.ptr_records : undefined}
                    {@const forward = sameIp ? dnsResults?.ptr_forward_records : undefined}
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
                            <VerdictFacts
                                raw={rawVerdict("iprev", iprev.result, iprev.details)}
                                links={sameIp
                                    ? [
                                          { href: "#dns-ptr", label: "Reverse DNS records" },
                                          { href: "#dns-fcrdns", label: "Forward confirmation" },
                                      ]
                                    : undefined}
                            >
                                {@render verdictRow("iprev", iprev.result)}
                                <FactRow label="Sending IP" value={iprev.ip} mono />
                                {#if iprev.hostname}
                                    <FactRow label="Its name" value={iprev.hostname} mono />
                                {/if}
                                {#snippet help()}
                                    {#if ptrs}
                                        <FactRow
                                            label="PTR records"
                                            value={ptrs.length ? ptrs.join(", ") : "none"}
                                            mono={ptrs.length > 0}
                                        />
                                    {/if}
                                    {#if ptrs?.length && forward}
                                        <FactRow
                                            label="Which resolve to"
                                            value={forward.length ? forward.join(", ") : "nothing"}
                                            mono={forward.length > 0}
                                            ok={!!iprev.ip && forward.includes(iprev.ip)}
                                            okLabel={iprev.ip && forward.includes(iprev.ip)
                                                ? "the sending IP"
                                                : "not the sending IP"}
                                        />
                                    {/if}
                                {/snippet}
                            </VerdictFacts>
                            <p class="check-about">
                                Receivers look up the name of the sending IP, and check that this
                                name resolves back to the same IP: a server without it looks like a
                                compromised home connection.
                            </p>
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
                            <VerdictFacts
                                raw={rawVerdict("x-ptr", xptr.result, xptr.details)}
                                links={dnsResults?.helo_hostname
                                    ? [{ href: "#dns-helo-ptr", label: "HELO / PTR consistency" }]
                                    : undefined}
                            >
                                {@render verdictRow("x_ptr", xptr.result, false)}
                                <FactRow label="Announced hostname" value={xptr.helo} mono />
                                <FactRow
                                    label="Name of the IP"
                                    value={xptr.ptr ?? "none"}
                                    mono={!!xptr.ptr}
                                />
                            </VerdictFacts>
                            <p class="check-about">
                                When it connects, the sending server announces its hostname (HELO or
                                EHLO). Many receivers check that it is the name its IP has in
                                reverse DNS; a mismatch is a common spam signal.
                            </p>
                        </div>
                    </CheckCard>
                {/if}

                {#if authentication.spf_helo}
                    {@const helo = authentication.spf_helo}
                    {@const record = spfRecordOf(helo.domain, dnsResults?.helo_spf_records)}
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
                            <VerdictFacts
                                raw={rawVerdict("spf", helo.result, helo.details)}
                                links={dnsResults?.helo_spf_records
                                    ? [{ href: "#dns-helo-spf", label: "SPF of the HELO hostname" }]
                                    : undefined}
                            >
                                {@render verdictRow("spf_helo", helo.result, false)}
                                <FactRow label="Announced hostname" value={helo.domain} mono />
                                {@render receiverNote(helo.details)}
                                {#snippet help()}
                                    {#if senderIp}
                                        <FactRow label="Sending IP" value={senderIp} mono />
                                    {/if}
                                    {@render spfRecordRow("SPF record", record)}
                                {/snippet}
                            </VerdictFacts>
                            <p class="check-about">
                                The same check as SPF, on the hostname the sending server announced
                                rather than on the envelope sender: it covers the bounces, which
                                have no envelope sender.
                            </p>
                        </div>
                    </CheckCard>
                {/if}

                {#if authentication.x_tls}
                    {@const xtls = authentication.x_tls}
                    {@const encrypted = xtls.result === "pass"}
                    <CheckCard
                        id="authentication-x-tls"
                        title="Transport encryption"
                        tag="TLS"
                        status={verdictStatus(xtls.result, true)}
                        summary={encrypted
                            ? tls?.version
                                ? `Encrypted, ${tls.version}`
                                : "Encrypted"
                            : "Not encrypted"}
                        docs={[docs.starttls]}
                        issues={at("x_tls")}
                    >
                        <div class="card-body">
                            <VerdictFacts
                                raw={rawVerdict("x-tls", xtls.result, xtls.details)}
                                links={tls?.fromHop
                                    ? [{ href: "#email-path", label: "Email path" }]
                                    : undefined}
                            >
                                <FactRow label="Connection">
                                    <span
                                        class="fw-semibold {statusTones[
                                            verdictStatus(xtls.result, true)
                                        ]}">{encrypted ? "encrypted" : "not encrypted"}</span
                                    >
                                    {#if verdictMeaning("x_tls", xtls.result)}
                                        <span class="fact-note"
                                            >{verdictMeaning("x_tls", xtls.result)}</span
                                        >
                                    {/if}
                                    {#if tls?.fromHop}
                                        <span class="fact-note">
                                            Read from the Received header the receiver wrote for the
                                            connection that delivered the message.
                                        </span>
                                    {/if}
                                </FactRow>
                                {#if tls?.version}
                                    <FactRow label="Protocol" value={tls.version} mono />
                                {/if}
                                {#if tls?.cipher}
                                    <FactRow label="Cipher" value={tls.cipher} mono />
                                {/if}
                                {#if tls?.bits}
                                    <FactRow label="Key size" value="{tls.bits} bits" />
                                {/if}
                                {#if tls?.verified !== undefined}
                                    <FactRow
                                        label="Certificate"
                                        value={tls.verified ? "verified" : "not verified"}
                                    />
                                {/if}
                                {#if tls?.transport}
                                    <FactRow label="Transport" value={tls.transport} mono />
                                {/if}
                            </VerdictFacts>
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
                    {#if authentication.spf}
                        {@const spf = authentication.spf}
                        {@const mailfrom = parseVerdictDetails(spf.details).properties[
                            "smtp.mailfrom"
                        ]}
                        {@const record = spfRecordOf(spf.domain)}
                        <VerdictFacts
                            raw={rawVerdict("spf", spf.result, spf.details)}
                            links={dnsResults?.spf_records
                                ? [{ href: "#dns-spf", label: "SPF record check" }]
                                : undefined}
                        >
                            {@render verdictRow("spf", spf.result)}
                            <FactRow label="Envelope sender" value={mailfrom || spf.domain} mono />
                            {@render receiverNote(spf.details)}
                            {#snippet help()}
                                {#if senderIp}
                                    <FactRow label="Sending IP" value={senderIp} mono />
                                {/if}
                                {@render spfRecordRow(
                                    spf.domain ? `SPF of ${spf.domain}` : "SPF record",
                                    record,
                                )}
                            {/snippet}
                        </VerdictFacts>
                        <p class="check-about">
                            The receiver checked that the sending IP is one the SPF record of the
                            envelope sender domain (the Return-Path, where bounces go) allows.
                        </p>
                    {:else if authentication.spf_helo}
                        <p class="check-about">
                            The receiver only checked the HELO identity, so it reported no verdict
                            for the envelope sender.
                        </p>
                    {:else}
                        <p class="check-about">
                            The receiver reported no SPF verdict. It checks that the sending IP is
                            one the SPF record of the envelope sender domain allows.
                        </p>
                    {/if}
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
                    {#each dkim as signature, i (i)}
                        {@const props = parseVerdictDetails(signature.details).properties}
                        {@const selector = signature.selector ?? props["header.s"]}
                        {@const key = dkimRecordOf(signature.domain, selector)}
                        {#if dkim.length > 1}
                            <h6 class={["small fw-semibold mb-1", i > 0 && "mt-3"]}>
                                Signature {i + 1} of {dkim.length}
                            </h6>
                        {/if}
                        <VerdictFacts
                            raw={rawVerdict("dkim", signature.result, signature.details)}
                            links={key
                                ? [{ href: "#dns-dkim", label: "DKIM record check" }]
                                : undefined}
                        >
                            {@render verdictRow("dkim", signature.result)}
                            {#if signature.domain}
                                <FactRow
                                    label="Signing domain (d=)"
                                    value={signature.domain}
                                    mono
                                />
                            {/if}
                            {#if selector}
                                <FactRow label="Selector (s=)" value={selector} mono />
                            {/if}
                            {#if props["header.a"]}
                                <FactRow label="Algorithm (a=)" value={props["header.a"]} mono />
                            {/if}
                            {@render receiverNote(signature.details)}
                            {#snippet help()}
                                {#if signature.domain && selector}
                                    <FactRow label="Public key">
                                        <span class="font-monospace"
                                            >{selector}._domainkey.{signature.domain}</span
                                        >
                                        {#if key}
                                            <span class="fact-note">
                                                {#if key.valid}
                                                    Published{key.key_type
                                                        ? `, ${key.key_type}`
                                                        : ""}{key.key_size
                                                        ? `, ${key.key_size} bits`
                                                        : ""}.
                                                {:else}
                                                    Not valid{key.error ? `: ${key.error}` : ""}.
                                                {/if}
                                            </span>
                                        {/if}
                                    </FactRow>
                                {/if}
                            {/snippet}
                        </VerdictFacts>
                    {/each}
                    <p class="check-about">
                        {#if dkim.length === 0}
                            The receiver reported no DKIM verdict: the message is likely not signed.
                        {:else}
                            The receiver checked each signature against the public key its domain
                            publishes in DNS.
                        {/if}
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
                    {#if authentication.dmarc}
                        {@const dmarc = authentication.dmarc}
                        {@const props = parseVerdictDetails(dmarc.details).properties}
                        {@const headerFrom = props["header.from"] ?? dmarc.domain}
                        {@const applied = props["policy.published-domain-policy"]}
                        <VerdictFacts
                            raw={rawVerdict("dmarc", dmarc.result, dmarc.details)}
                            links={[
                                ...(dmarcRecord
                                    ? [{ href: "#dns-dmarc", label: "DMARC record check" }]
                                    : []),
                                { href: "#domain-alignment", label: "Domain alignment" },
                            ]}
                        >
                            {@render verdictRow("dmarc", dmarc.result)}
                            {#if headerFrom}
                                <FactRow label="From domain" value={headerFrom} mono />
                            {/if}
                            {#if applied}
                                <FactRow label="Policy" value={applied} mono />
                            {/if}
                            {@render receiverNote(dmarc.details)}
                            {#snippet help()}
                                <!-- The verdicts DMARC rests on: one of them passing for the
                                     From domain is enough. -->
                                <FactRow label="SPF">
                                    {#if authentication.spf}
                                        <span
                                            class={statusTones[
                                                verdictStatus(authentication.spf.result, true)
                                            ]}>{authentication.spf.result}</span
                                        >
                                        {#if authentication.spf.domain}
                                            for
                                            <span class="font-monospace"
                                                >{authentication.spf.domain}</span
                                            >
                                        {/if}
                                    {:else}
                                        <span class="text-body-secondary">not reported</span>
                                    {/if}
                                </FactRow>
                                <FactRow label="DKIM">
                                    {#each dkim as signature, i (i)}
                                        <span class="d-block">
                                            <span
                                                class={statusTones[
                                                    verdictStatus(signature.result, true)
                                                ]}>{signature.result}</span
                                            >
                                            {#if signature.domain}
                                                for
                                                <span class="font-monospace"
                                                    >{signature.domain}</span
                                                >
                                            {/if}
                                        </span>
                                    {:else}
                                        <span class="text-body-secondary">no signature</span>
                                    {/each}
                                </FactRow>
                                {#if dmarcRecord?.record}
                                    <FactRow label="DMARC record">
                                        <code>{dmarcRecord.record}</code>
                                    </FactRow>
                                {/if}
                            {/snippet}
                        </VerdictFacts>
                    {/if}
                    <p class="check-about">
                        DMARC passes when SPF or DKIM passes for a domain aligned with the From
                        address, the one the recipient sees. Otherwise the receiver applies the
                        policy the From domain publishes.
                    </p>
                </div>
            </CheckCard>

            {#if authentication.x_aligned_from}
                {@const aligned = authentication.x_aligned_from}
                {@const sameOrg = isAlignedWith(
                    envelopeDomain,
                    alignment?.return_path_org_domain,
                    fromDomain,
                    alignment?.from_org_domain,
                )}
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
                        <VerdictFacts
                            raw={rawVerdict("x-aligned-from", aligned.result, aligned.details)}
                            links={[{ href: "#domain-alignment", label: "Domain alignment" }]}
                        >
                            {@render verdictRow("x_aligned_from", aligned.result, false)}
                            {@render receiverNote(aligned.details)}
                            {#snippet help()}
                                {#if envelopeDomain}
                                    <FactRow
                                        label="Envelope sender domain"
                                        value={envelopeDomain}
                                        mono
                                    />
                                {/if}
                                {#if fromDomain}
                                    <FactRow
                                        label="From domain"
                                        value={fromDomain}
                                        mono
                                        ok={sameOrg}
                                        okLabel={sameOrg === undefined
                                            ? undefined
                                            : sameOrg
                                              ? "aligned"
                                              : "not aligned"}
                                    />
                                {/if}
                            {/snippet}
                        </VerdictFacts>
                        <p class="check-about">
                            Whether the envelope sender and the From address are in the same domain.
                        </p>
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
                    {#if authentication.bimi}
                        {@const bimi = authentication.bimi}
                        {@const props = parseVerdictDetails(bimi.details).properties}
                        {@const policy = dmarcRecord?.policy}
                        {@const enforced = policy === "quarantine" || policy === "reject"}
                        <VerdictFacts
                            raw={rawVerdict("bimi", bimi.result, bimi.details)}
                            links={[{ href: "#dns-bimi", label: "BIMI record check" }]}
                        >
                            {@render verdictRow("bimi", bimi.result, false)}
                            {#if bimi.domain ?? props["header.d"]}
                                <FactRow
                                    label="Domain"
                                    value={bimi.domain ?? props["header.d"]}
                                    mono
                                />
                            {/if}
                            {#if props["header.selector"]}
                                <FactRow label="Selector" value={props["header.selector"]} mono />
                            {/if}
                            {@render receiverNote(bimi.details)}
                            {#snippet help()}
                                {#if policy}
                                    <FactRow
                                        label="DMARC policy"
                                        value={policy}
                                        mono
                                        ok={enforced}
                                        okLabel={enforced
                                            ? "at enforcement"
                                            : "BIMI needs quarantine or reject"}
                                    />
                                {/if}
                            {/snippet}
                        </VerdictFacts>
                    {/if}
                    <p class="check-about">
                        Whether the receiver would display your brand logo next to the message. The
                        record and the logo are checked with the <a href="#dns-bimi">DNS records</a
                        >.
                    </p>
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
                            <VerdictFacts
                                raw={rawVerdict("x-google-dkim", google.result, google.details)}
                            >
                                {@render verdictRow("dkim", google.result, false)}
                                {#if google.domain}
                                    <FactRow label="Signing domain" value={google.domain} mono />
                                {/if}
                            </VerdictFacts>
                            <p class="check-about">
                                Google signs the messages it routes; a signature that no longer
                                verifies means something changed the message afterwards.
                            </p>
                        </div>
                    </CheckCard>
                {/if}

                {#if authentication.arc}
                    {@const arc = authentication.arc}
                    {@const raw = rawVerdict("arc", arc.result, arc.details)}
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
                            <!-- The analyser words its own verdict when it checked the chain
                                 itself: only the receiver's is raw. -->
                            <VerdictFacts raw={raw?.startsWith("arc=") ? raw : undefined}>
                                {@render verdictRow("arc", arc.result, false)}
                                {#if arc.chain_length !== undefined}
                                    <FactRow
                                        label="Intermediaries"
                                        value={String(arc.chain_length)}
                                    />
                                {/if}
                                {#if arc.chain_valid !== undefined}
                                    <FactRow
                                        label="Seals"
                                        value={arc.chain_valid ? "all verify" : "broken"}
                                    />
                                {/if}
                                {#if raw && !raw.startsWith("arc=")}
                                    <FactRow label="Details" value={raw} />
                                {/if}
                            </VerdictFacts>
                            <p class="check-about">
                                The seals of the intermediaries that forwarded the message, vouching
                                for the authentication results it had when they received it.
                            </p>
                        </div>
                    </CheckCard>
                {/if}
            </CheckList>
        {/if}
    </div>
</ReportSection>
