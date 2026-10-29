<script lang="ts">
    import type { Issue, SenderDomainInfo } from "#lib/api/types.gen.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        domainInfo?: SenderDomainInfo;
        // Which sender identity the domain is: changes what a throwaway
        // provider means.
        role?: "from" | "return-path";
        issues?: Issue[];
    }

    let { domainInfo, role = "from", issues }: Props = $props();

    const created = $derived(
        domainInfo?.creation_date ? new Date(domainInfo.creation_date) : undefined,
    );
    const expires = $derived(
        domainInfo?.expiration_date ? new Date(domainInfo.expiration_date) : undefined,
    );
    const expired = $derived(expires !== undefined && expires.getTime() < Date.now());
    const daysToExpiry = $derived(
        expires ? Math.floor((expires.getTime() - Date.now()) / 86400000) : undefined,
    );
    // A registration that still has months to run says nothing about the mail:
    // the domain resolves, so it has not expired. Only a renewal that is close
    // enough to break delivery is worth a line.
    const expiringSoon = $derived(daysToExpiry !== undefined && daysToExpiry <= 30);

    const ageDays = $derived(domainInfo?.age_days);
    const young = $derived(ageDays !== undefined && ageDays < 90);
    const ageLabel = $derived.by(() => {
        if (ageDays === undefined) return undefined;
        if (ageDays < 1) return "Registered today";
        if (ageDays < 60) return `Registered ${ageDays} day${ageDays === 1 ? "" : "s"} ago`;
        const months = Math.floor(ageDays / 30);
        if (ageDays < 730) return `Registered ${months} month${months === 1 ? "" : "s"} ago`;
        const years = Math.floor(ageDays / 365);
        return `Registered ${years} year${years === 1 ? "" : "s"} ago`;
    });

    // Same reading for the renewal: how long is left, not the calendar date.
    const expiryLabel = $derived.by(() => {
        if (daysToExpiry === undefined) return undefined;
        if (daysToExpiry < 0) {
            const days = -daysToExpiry;
            return `Expired ${days} day${days === 1 ? "" : "s"} ago`;
        }
        if (daysToExpiry < 1) return "Expires today";
        return `Expires in ${daysToExpiry} day${daysToExpiry === 1 ? "" : "s"}`;
    });

    const lapsing = $derived(domainInfo?.lapsing ?? false);
    const concerning = $derived(young || lapsing || expired || expiringSoon);

    const hasRegistration = $derived(
        domainInfo !== undefined &&
            (domainInfo.registrar !== undefined ||
                created !== undefined ||
                expired ||
                expiringSoon ||
                lapsing ||
                domainInfo.registrant_country !== undefined),
    );
</script>

<!-- Who the domain is: a throwaway or public mailbox provider, and what the registry says
     about it. -->
{#if domainInfo && (hasRegistration || domainInfo.error || domainInfo.disposable || domainInfo.free_provider)}
    <CheckCard
        id="dns-registration-{role}"
        title="Domain Registration"
        tag="RDAP / WHOIS"
        status={domainInfo.error && !domainInfo.disposable && !domainInfo.free_provider
            ? "neutral"
            : domainInfo.disposable || lapsing || expired
              ? "fail"
              : concerning
                ? "warn"
                : domainInfo.free_provider
                  ? "info"
                  : "pass"}
        summary={domainInfo.error
            ? `${domainInfo.domain}: ${domainInfo.error}`
            : [
                  domainInfo.domain,
                  [ageLabel?.toLowerCase(), domainInfo.registrar && `at ${domainInfo.registrar}`]
                      .filter(Boolean)
                      .join(" "),
              ]
                  .filter(Boolean)
                  .join(", ")}
        summaryFoldedOnly={!!domainInfo.error}
        {issues}
    >
        <div class="card-body">
            <dl class="check-facts">
                {#if domainInfo.disposable || domainInfo.free_provider}
                    <dt>Provider</dt>
                    <dd>
                        {domainInfo.disposable ? "disposable addresses" : "public mailbox service"}
                    </dd>
                {/if}
                {#if created}
                    <dt>Registered</dt>
                    <dd>
                        <span class:text-warning-emphasis={young}>{ageLabel}</span>
                        <span class="text-body-secondary">({created.toLocaleDateString()})</span>
                    </dd>
                {/if}
                {#if expires && (expired || expiringSoon)}
                    <dt>Expires</dt>
                    <dd>
                        <span class={expired ? "text-danger" : "text-warning-emphasis"}
                            >{expiryLabel}</span
                        >
                        <span class="text-body-secondary">({expires.toLocaleDateString()})</span>
                    </dd>
                {/if}
                {#if lapsing}
                    <dt>Status</dt>
                    <dd class="text-danger">being deleted or held out of the DNS</dd>
                {/if}
                {#if domainInfo.registrar}
                    <dt>Registrar</dt>
                    <dd>
                        {#if domainInfo.registrar_url}
                            <!-- eslint-disable svelte/no-navigation-without-resolve -- external URL, not a SvelteKit route -->
                            <a
                                href={domainInfo.registrar_url}
                                target="_blank"
                                rel="noopener noreferrer">{domainInfo.registrar}</a
                            >
                            <!-- eslint-enable svelte/no-navigation-without-resolve -->
                        {:else}
                            {domainInfo.registrar}
                        {/if}
                    </dd>
                {/if}
                {#if domainInfo.registrant_country}
                    <dt>Registrant country</dt>
                    <dd>{domainInfo.registrant_country}</dd>
                {/if}
                {#if domainInfo.error}
                    <dt>Lookup</dt>
                    <dd>{domainInfo.error}</dd>
                {/if}
            </dl>
            <p class="check-about">
                What the registry publishes about <span class="font-monospace"
                    >{domainInfo.domain}</span
                >. Receivers distrust domains registered recently, a week-old domain being what a
                campaign registers the day before it sends; and mail from a domain whose
                registration is lapsing is about to stop working.
            </p>
        </div>
    </CheckCard>
{/if}
