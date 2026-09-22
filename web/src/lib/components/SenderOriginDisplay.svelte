<script lang="ts">
    import type { IpOrigin } from "$lib/api/types.gen";

    interface Props {
        senderOrigin?: IpOrigin;
    }

    let { senderOrigin }: Props = $props();

    const allocated = $derived(
        senderOrigin?.allocated ? new Date(senderOrigin.allocated) : undefined,
    );

    // A block allocated long ago usually belongs to an operator that has been
    // around; a fresh one carries no history for receivers to weigh.
    const allocatedYears = $derived(
        allocated
            ? Math.floor((Date.now() - allocated.getTime()) / (365.25 * 24 * 3600 * 1000))
            : undefined,
    );

    // How each source signs itself, so the card names who answered rather than
    // assuming one implementation. An unknown source is shown as it came.
    const sourceNames: Record<string, string> = {
        cymru: "Team Cymru IP-to-ASN",
        maxmind: "MaxMind GeoIP",
    };
    const sourceLabel = $derived(
        senderOrigin ? (sourceNames[senderOrigin.source] ?? senderOrigin.source) : undefined,
    );

    // The country means different things depending on who answered it: a
    // registry service says where the block was allocated, a geolocation
    // database where the address is believed to be used.
    const countrySource = $derived(senderOrigin?.country_source ?? senderOrigin?.source);
    const countryIsLocated = $derived(countrySource === "maxmind");
    const countrySourceLabel = $derived(
        countrySource ? (sourceNames[countrySource] ?? countrySource) : undefined,
    );

    // Regional flag from the two-letter code, so the country reads at a glance.
    const flag = $derived.by(() => {
        const code = senderOrigin?.country;
        if (!code || !/^[A-Za-z]{2}$/.test(code)) return undefined;
        return String.fromCodePoint(
            ...code
                .toUpperCase()
                .split("")
                .map((c) => 0x1f1e6 + c.charCodeAt(0) - 65),
        );
    });
</script>

{#if senderOrigin}
    <div class="card mb-4" id="dns-origin">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="text-muted mb-0">
                <i class="bi bi-globe-americas text-secondary"></i>
                Sender Network
            </h5>
            <span class="badge bg-secondary">{sourceLabel}</span>
        </div>
        <div class="card-body">
            <p class="card-text small text-muted mb-0">
                Every address on the Internet is announced by one network, identified by an
                <abbr title="Autonomous System">AS</abbr> number: a hosting provider, a mail service,
                an access provider. Receivers do not score that network, but they do weigh its reputation,
                so knowing who carries your mail tells you whose reputation you are borrowing.
            </p>
        </div>
        <div class="list-group list-group-flush">
            {#if senderOrigin.asn}
                <div class="list-group-item">
                    <strong>Announced by:</strong>
                    {#if senderOrigin.as_name}
                        {senderOrigin.as_name}
                    {/if}
                    <a
                        href="https://bgp.tools/as/{senderOrigin.asn}"
                        target="_blank"
                        rel="noopener noreferrer"
                        class="text-decoration-none"
                    >
                        <code>AS{senderOrigin.asn}</code>
                    </a>
                    {#if senderOrigin.prefix}
                        <div class="small text-muted mt-1">
                            The address sits in <code>{senderOrigin.prefix}</code>, the block this
                            operator announces to the rest of the Internet.
                        </div>
                    {/if}
                </div>
            {/if}
            {#if senderOrigin.country}
                <div class="list-group-item">
                    <strong>{countryIsLocated ? "Located in:" : "Registered in:"}</strong>
                    {#if flag}<span class="me-1">{flag}</span>{/if}
                    {senderOrigin.country_name ?? senderOrigin.country}
                    <span class="text-muted">({senderOrigin.country})</span>
                    <div class="small text-muted mt-1">
                        {#if countryIsLocated}
                            Where {countrySourceLabel} believes the address is used. Geolocation is an
                            estimate.
                        {:else}
                            Where the address block was allocated by its Internet registry, not
                            necessarily where the server stands nor where the company operates.
                        {/if}
                    </div>
                </div>
            {/if}
            {#if senderOrigin.registry || allocated}
                <div class="list-group-item">
                    <strong>Allocated:</strong>
                    {#if allocated}
                        {allocated.toLocaleDateString()}
                        {#if allocatedYears !== undefined && allocatedYears >= 1}
                            <span class="text-muted">
                                ({allocatedYears} year{allocatedYears === 1 ? "" : "s"} ago)
                            </span>
                        {/if}
                    {/if}
                    {#if senderOrigin.registry}
                        by the <code>{senderOrigin.registry.toUpperCase()}</code> registry
                    {/if}
                </div>
            {/if}
        </div>
    </div>
{/if}
