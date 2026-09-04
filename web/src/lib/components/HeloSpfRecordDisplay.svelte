<script lang="ts">
    import type { SpfRecord } from "$lib/api/types.gen";

    interface Props {
        heloSpfRecord?: SpfRecord;
        // Envelope sender domain, and its organizational domain when the backend
        // resolved one through the Public Suffix List
        senderDomain?: string;
        senderOrgDomain?: string;
    }

    let { heloSpfRecord, senderDomain, senderOrgDomain }: Props = $props();

    // A published policy is a bonus, never a requirement: its absence is shown as
    // a recommendation, so nothing here is ever styled as an error.
    const hasPolicy = $derived(!!heloSpfRecord?.valid);

    const normalize = (host: string) => host.replace(/\.$/, "").trim().toLowerCase();

    // Who can act on the recommendation: the HELO name sits under the sender's own
    // domain (they run the server and can publish the record themselves), or it
    // belongs to someone else's infrastructure (only that provider can publish it).
    const ownInfrastructure = $derived.by(() => {
        const helo = heloSpfRecord?.domain;
        if (!helo) return false;

        const announced = normalize(helo);

        return [senderDomain, senderOrgDomain]
            .filter((domain): domain is string => !!domain)
            .map(normalize)
            .some((domain) => announced === domain || announced.endsWith(`.${domain}`));
    });

    // The `a` mechanism authorizes the host's own address, which is what a HELO
    // name resolves to: it stays correct even when the server changes IP, and it
    // matches the A and AAAA records alike (RFC 7208, section 5.3).
    const suggestedRecord = $derived(`${heloSpfRecord?.domain}. IN TXT "v=spf1 a -all"`);
</script>

{#if heloSpfRecord}
    <div class="card mb-4" id="dns-helo-spf">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="text-muted mb-0">
                <i
                    class="bi"
                    class:bi-check-circle-fill={hasPolicy}
                    class:text-success={hasPolicy}
                    class:bi-info-circle-fill={!hasPolicy}
                    class:text-info={!hasPolicy}
                ></i>
                SPF for the HELO Hostname
            </h5>
            <span class="badge bg-secondary">SPF</span>
        </div>
        <div class="card-body">
            <p class="card-text small text-muted mb-0">
                SPF can authenticate, in addition to the envelope sender, the hostname the sending
                server announces at HELO.
                <a
                    href="https://www.rfc-editor.org/rfc/rfc7208.html#section-2.3"
                    target="_blank"
                    rel="noreferrer">RFC 7208, section 2.3</a
                >
                recommends that receivers check that identity, and notes that records published for it
                <q>refer to a single host</q>
                and are therefore
                <q>a very reliable source of host authorization status</q>. It also matters for
                bounce messages: their envelope sender is empty, so
                <a
                    href="https://www.rfc-editor.org/rfc/rfc7208.html#section-2.4"
                    target="_blank"
                    rel="noreferrer">section 2.4</a
                >
                has receivers check <code>postmaster@</code> the HELO name instead, making it the only
                identity SPF can evaluate there. Publishing such a policy stays optional: this check never
                affects your score.
            </p>
            {#if heloSpfRecord.domain}
                <div class="mt-2">
                    <strong>Announced HELO:</strong> <code>{heloSpfRecord.domain}</code>
                </div>
            {/if}
            <div class="mt-1">
                <strong>Record:</strong>
                {#if heloSpfRecord.record}
                    <code class="text-break">{heloSpfRecord.record}</code>
                {:else}
                    <!-- Report what the lookup actually returned: "no record published" would
                         hide a hostname that does not resolve at all -->
                    {heloSpfRecord.error ?? "no record published"}
                {/if}
            </div>
        </div>
        <div class="list-group list-group-flush">
            <div class="list-group-item">
                {#if hasPolicy}
                    <div class="alert alert-success mb-0">
                        <i class="bi bi-check-circle me-1"></i>
                        This hostname publishes its own SPF policy, so receivers can authenticate the
                        HELO identity as well as the envelope sender.
                    </div>
                {:else}
                    <div class="alert alert-info mb-0">
                        <i class="bi bi-info-circle me-1"></i>
                        <strong>Recommendation:</strong>
                        {#if heloSpfRecord.record && ownInfrastructure}
                            fix the policy published for <code>{heloSpfRecord.domain}</code>, which
                            could not be validated ({heloSpfRecord.error}). Receivers could then
                            authenticate the HELO identity as well as the envelope sender.
                        {:else if heloSpfRecord.record}
                            report to your email provider that the policy published for
                            <code>{heloSpfRecord.domain}</code>
                            could not be validated ({heloSpfRecord.error}). That hostname belongs to
                            the infrastructure that relayed your message, so only its operator can
                            fix it.
                        {:else if ownInfrastructure}
                            publish a policy for <code>{heloSpfRecord.domain}</code> too. That hostname
                            is part of your own domain, so you can add the record yourself:
                        {:else}
                            ask your email provider to publish a policy for
                            <code>{heloSpfRecord.domain}</code>. That hostname belongs to the
                            infrastructure that relayed your message, not to your domain, so only
                            its operator can add the record:
                        {/if}
                        {#if !heloSpfRecord.record}
                            <pre class="mb-0 mt-2"><code class="text-break">{suggestedRecord}</code
                                ></pre>
                            <div class="small mt-2">
                                The <code>a</code> mechanism authorizes the address the hostname
                                itself resolves to, so the record stays correct if the server
                                changes IP. It assumes that hostname resolves: if the lookup above
                                failed instead of reporting no policy, the missing A/AAAA record is
                                what to publish first, as <code>a</code> would otherwise match nothing.
                            </div>
                        {/if}
                    </div>
                {/if}
            </div>
        </div>
    </div>
{/if}
