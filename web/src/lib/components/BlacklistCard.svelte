<script lang="ts">
    import { resolve } from "$app/paths";
    import { page } from "$app/state";

    import type { BlacklistCheck } from "#lib/api/types.gen.js";
    import { docs, rblLookupLink } from "#lib/docs.js";
    import type { SectionStatus } from "#lib/sections.js";
    import DocLinks from "./DocLinks.svelte";
    import ReportSection from "./ReportSection.svelte";

    interface Props {
        blacklists: Record<string, BlacklistCheck[]>;
        blacklistGrade?: string;
        blacklistScore?: number;
        status?: SectionStatus;
        open?: boolean;
    }

    let { blacklists, blacklistGrade, blacklistScore, status, open = true }: Props = $props();

    // A clean result is the expected one: what a reader needs is the lists that do list the
    // address, then those that could not answer. The clean ones are folded into a count.
    const addresses = $derived(
        Object.entries(blacklists).map(([ip, checks]) => ({
            ip,
            total: checks.length,
            listed: checks.filter((c) => c.listed),
            // Listed for its network, not for what it sent: the check says which lists those are.
            ownListings: checks.filter((c) => c.listed && !c.informational).length,
            errored: checks.filter((c) => !c.listed && c.error),
            clean: checks.filter((c) => !c.listed && !c.error),
        })),
    );

    // On the page dedicated to one address, a link to check that address again goes nowhere.
    const onAddressPage = $derived(page.route.id === "/blacklist/[ip]");
</script>

<ReportSection
    id="rbl-details"
    title="Blacklist Checks"
    icon="shield-exclamation"
    grade={blacklistGrade}
    score={blacklistScore}
    {status}
    {open}
>
    <div class="list-group list-group-flush">
        {#each addresses as address (address.ip)}
            <div class="list-group-item py-3">
                <div class="d-flex flex-wrap align-items-center gap-2 mb-2">
                    <i class="bi bi-hdd-network text-muted" aria-hidden="true"></i>
                    <code class="fs-6">{address.ip}</code>
                    {#if address.listed.length > 0}
                        <span class="badge bg-danger">
                            Listed on {address.listed.length} of {address.total}
                        </span>
                    {:else}
                        <span class="badge bg-success">
                            Not listed on any of the {address.total - address.errored.length} lists that
                            answered
                        </span>
                    {/if}
                    {#if !onAddressPage}
                        <a
                            class="small ms-auto"
                            href={resolve("/blacklist/[ip]", { ip: address.ip })}
                        >
                            Check this IP again<i class="bi bi-arrow-right-short" aria-hidden="true"
                            ></i>
                        </a>
                    {/if}
                </div>

                {#if address.listed.length > 0}
                    <ul class="list-unstyled mb-2">
                        {#each address.listed as check (check.rbl)}
                            {@const lookup = rblLookupLink(check.rbl)}
                            {@const network = !!check.informational}
                            <li
                                class={[
                                    "d-flex flex-wrap align-items-baseline gap-2 px-2 py-1 mb-1 rounded-1",
                                    network ? "bg-warning-subtle" : "bg-danger-subtle",
                                ]}
                            >
                                <i
                                    class="bi {network
                                        ? 'bi-exclamation-circle-fill text-warning'
                                        : 'bi-x-circle-fill text-danger'}"
                                    aria-hidden="true"
                                ></i>
                                <code>{check.rbl}</code>
                                {#if network}
                                    <span
                                        class="badge bg-secondary"
                                        title="This list covers whole address ranges or providers: few receivers use it, and the score only takes a flat penalty for it"
                                    >
                                        network-wide
                                    </span>
                                {/if}
                                {#if check.response}
                                    <span class="small text-muted">returned {check.response}</span>
                                {/if}
                                {#if lookup}
                                    <!-- eslint-disable svelte/no-navigation-without-resolve -- the list's own site -->
                                    <a
                                        class="small ms-auto"
                                        href={lookup.url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                    >
                                        Why, and how to get delisted
                                        <i class="bi bi-box-arrow-up-right" aria-hidden="true"></i>
                                    </a>
                                    <!-- eslint-enable svelte/no-navigation-without-resolve -->
                                {/if}
                            </li>
                        {/each}
                    </ul>
                    {#if address.ownListings > 0}
                        <p class="small text-muted mb-2">
                            Find out what got the address listed (a compromised account, an open
                            relay, purchased or stale recipient lists) and fix it before asking for
                            removal: most lists delist on their own once the cause stops, and list
                            the address again if it does not.
                        </p>
                    {:else}
                        <p class="small text-muted mb-2">
                            Only lists covering whole networks name this address: that comes from
                            its neighbours rather than from your mail. Ask your hosting provider
                            about it.
                        </p>
                    {/if}
                {/if}

                {#if address.errored.length > 0}
                    <p class="small text-muted mb-2">
                        <i class="bi bi-question-circle me-1" aria-hidden="true"></i>
                        {address.errored.length} list{address.errored.length > 1 ? "s" : ""} did not answer:
                        {#each address.errored as check, i (check.rbl)}
                            <code title={check.error}>{check.rbl}</code>{i <
                            address.errored.length - 1
                                ? ", "
                                : ""}
                        {/each}
                    </p>
                {/if}

                {#if address.clean.length > 0}
                    <details class="passed-items">
                        <summary>
                            <i class="bi bi-check-circle-fill text-success me-1"></i>
                            Clean on {address.clean.length} list{address.clean.length > 1
                                ? "s"
                                : ""}
                        </summary>
                        <ul class="clean-lists list-unstyled small mt-2 mb-0">
                            {#each address.clean as check (check.rbl)}
                                <li><code>{check.rbl}</code></li>
                            {/each}
                        </ul>
                    </details>
                {/if}
            </div>
        {/each}
    </div>
    <div class="card-footer">
        <DocLinks docs={[docs.dnsbl]} />
    </div>
</ReportSection>

<style>
    .clean-lists {
        columns: 2 14rem;
    }
</style>
