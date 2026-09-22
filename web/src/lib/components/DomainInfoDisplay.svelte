<script lang="ts">
    import type { SenderDomainInfo } from "$lib/api/types.gen";

    interface Props {
        domainInfo?: SenderDomainInfo;
        // Which sender identity the domain is: changes what a throwaway
        // provider means.
        role?: "from" | "return-path";
    }

    let { domainInfo, role = "from" }: Props = $props();

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

{#if domainInfo}
    {#if domainInfo.disposable}
        <div class="alert alert-danger mb-3">
            <i class="bi bi-trash3 me-1"></i>
            <strong>Disposable address provider:</strong>
            <code>{domainInfo.domain}</code> hands out throwaway addresses.
            {#if role === "from"}
                Receivers refuse or quarantine mail whose visible sender is a throwaway address.
                Send from a domain you control.
            {:else}
                Bounces and delivery reports for this message go to a mailbox nobody will read. Use
                a Return-Path at a domain you control.
            {/if}
        </div>
    {:else if domainInfo.free_provider}
        <div class="alert alert-info mb-3">
            <i class="bi bi-person me-1"></i>
            <strong>Free mailbox provider:</strong>
            <code>{domainInfo.domain}</code> is a public mailbox service. That is fine for personal mail
            sent through the provider itself; bulk or transactional mail in its name from another server
            fails the provider's own DMARC policy. Use a domain you control for that.
        </div>
    {/if}

    {#if domainInfo.error}
        <p class="small text-muted mb-3">
            <i class="bi bi-info-circle me-1"></i>
            Registration of <code>{domainInfo.domain}</code>: {domainInfo.error}
        </p>
    {:else if hasRegistration}
        <div class="card mb-4" id="dns-registration-{role}">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="text-muted mb-0">
                    <i
                        class="bi"
                        class:bi-check-circle-fill={!concerning}
                        class:text-success={!concerning}
                        class:bi-exclamation-triangle-fill={concerning}
                        class:text-warning={concerning}
                    ></i>
                    Domain Registration
                </h5>
                <span class="badge bg-secondary">RDAP / WHOIS</span>
            </div>
            <div class="card-body">
                <p class="card-text small text-muted mb-0">
                    What the registry publishes about <code>{domainInfo.domain}</code>. Receivers
                    distrust domains registered recently, a week-old domain being what a campaign
                    registers the day before it sends; and mail from a domain whose registration is
                    lapsing is about to stop working.
                </p>
            </div>
            <div class="list-group list-group-flush">
                {#if created}
                    <div class="list-group-item">
                        <i
                            class="bi me-1"
                            class:bi-check-circle-fill={!young}
                            class:text-success={!young}
                            class:bi-exclamation-triangle-fill={young}
                            class:text-warning={young}
                        ></i>
                        <strong>{ageLabel ?? "Registered"}</strong>
                        <span class="text-muted">({created.toLocaleDateString()})</span>
                        <div class="small text-muted mt-1">
                            {#if young}
                                Young domains have no reputation yet; expect stricter filtering for
                                the first months.
                            {:else}
                                Old enough for receivers to have a history to weigh.
                            {/if}
                        </div>
                    </div>
                {/if}
                {#if expires && (expired || expiringSoon)}
                    <div class="list-group-item">
                        <i
                            class="bi me-1"
                            class:bi-x-circle-fill={expired}
                            class:text-danger={expired}
                            class:bi-exclamation-triangle-fill={!expired}
                            class:text-warning={!expired}
                        ></i>
                        <strong>{expiryLabel}</strong>
                        <span class="text-muted">({expires.toLocaleDateString()})</span>
                        <div class="small text-muted mt-1">
                            Renew the registration before the domain is deleted and its mail stops
                            working.
                        </div>
                    </div>
                {/if}
                {#if domainInfo.registrar}
                    <div class="list-group-item">
                        <strong>Registrar:</strong>
                        {#if domainInfo.registrar_url}
                            <a
                                href={domainInfo.registrar_url}
                                target="_blank"
                                rel="noopener noreferrer"
                            >
                                {domainInfo.registrar}
                            </a>
                        {:else}
                            {domainInfo.registrar}
                        {/if}
                    </div>
                {/if}
                {#if domainInfo.registrant_country}
                    <div class="list-group-item">
                        <strong>Registrant country:</strong>
                        {domainInfo.registrant_country}
                    </div>
                {/if}
                {#if lapsing}
                    <div class="list-group-item">
                        <div class="alert alert-danger mb-0">
                            <i class="bi bi-x-circle me-1"></i>
                            The registry is deleting this domain or holding it out of the DNS: mail to
                            and from it is about to stop working.
                        </div>
                    </div>
                {/if}
            </div>
        </div>
    {/if}
{/if}
