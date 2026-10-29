<script lang="ts">
    import type { BlacklistCheck } from "#lib/api/types.gen.js";
    import ReportSection from "./ReportSection.svelte";

    interface Props {
        whitelists: Record<string, BlacklistCheck[]>;
        open?: boolean;
    }

    let { whitelists, open = true }: Props = $props();

    const addresses = $derived(
        Object.entries(whitelists).map(([ip, checks]) => ({
            ip,
            listed: checks.filter((c) => c.listed),
            others: checks.filter((c) => !c.listed),
        })),
    );

    const listedCount = $derived(addresses.reduce((n, a) => n + a.listed.length, 0));
</script>

<ReportSection
    id="dnswl-details"
    title="Whitelist Checks"
    icon="shield-check"
    status={{
        label:
            listedCount > 0
                ? `Listed on ${listedCount} whitelist${listedCount > 1 ? "s" : ""}`
                : "Not whitelisted",
        tone: listedCount > 0 ? "success" : "muted",
        needsAttention: false,
    }}
    {open}
>
    {#snippet aside()}
        <span class="badge bg-info">Informational</span>
    {/snippet}
    <div class="card-body">
        <p class="text-muted small mb-3">
            DNS whitelists identify trusted senders. Being listed here is a positive signal, but has
            no impact on the overall score.
        </p>

        {#each addresses as address (address.ip)}
            <div class="mb-2">
                <div class="d-flex flex-wrap align-items-center gap-2 mb-1">
                    <i class="bi bi-hdd-network text-muted" aria-hidden="true"></i>
                    <code>{address.ip}</code>
                    {#each address.listed as check (check.rbl)}
                        <span class="badge bg-success" title={check.response}>
                            <i class="bi bi-check-circle-fill me-1" aria-hidden="true"></i>
                            {check.rbl}
                        </span>
                    {/each}
                </div>
                {#if address.others.length > 0}
                    <details class="passed-items">
                        <summary>
                            Not listed on {address.others.length} whitelist{address.others.length >
                            1
                                ? "s"
                                : ""}
                        </summary>
                        <ul class="list-unstyled small mt-1 mb-0">
                            {#each address.others as check (check.rbl)}
                                <li>
                                    <code>{check.rbl}</code>
                                    {#if check.error}
                                        <span class="text-muted">(error: {check.error})</span>
                                    {/if}
                                </li>
                            {/each}
                        </ul>
                    </details>
                {/if}
            </div>
        {/each}
    </div>
</ReportSection>
