<script lang="ts">
    import type { DomainBlacklistSourceResult } from "$lib/api/types.gen";
    import { theme } from "$lib/stores/theme";

    interface Props {
        results: DomainBlacklistSourceResult[];
    }

    let { results }: Props = $props();

    // Paid sources that show a "configure API key" hint when disabled.
    const paidSourceIds = new Set(["virustotal", "safebrowsing"]);

    type Bucket = "listed" | "errored" | "clean" | "disabled";

    function classify(r: DomainBlacklistSourceResult): Bucket {
        if (!r.enabled) return "disabled";
        if (r.error) return "errored";
        if (r.listed) return "listed";
        return "clean";
    }

    function severityRank(sev: string | undefined): number {
        switch (sev) {
            case "crit":
                return 0;
            case "warn":
                return 1;
            case "info":
                return 2;
            default:
                return 3;
        }
    }

    function bucketRank(b: Bucket): number {
        switch (b) {
            case "listed":
                return 0;
            case "errored":
                return 1;
            case "clean":
                return 2;
            case "disabled":
                return 3;
        }
    }

    let sorted = $derived(
        [...results].sort((a, b) => {
            const ba = classify(a);
            const bb = classify(b);
            if (ba !== bb) return bucketRank(ba) - bucketRank(bb);
            if (ba === "listed") {
                const r = severityRank(a.severity) - severityRank(b.severity);
                if (r !== 0) return r;
            }
            return a.source_name.localeCompare(b.source_name);
        }),
    );

    function statusLabel(r: DomainBlacklistSourceResult): string {
        if (!r.enabled) return "Disabled";
        if (r.error) return "Error";
        if (r.listed) {
            if (r.severity && r.severity !== "ok") {
                return `Listed (${r.severity})`;
            }
            return "Listed";
        }
        return "Clean";
    }

    function statusBadgeClass(r: DomainBlacklistSourceResult): string {
        if (!r.enabled) return "bg-secondary";
        if (r.error) return "bg-dark";
        if (r.listed) {
            switch (r.severity) {
                case "crit":
                    return "bg-danger";
                case "warn":
                    return "bg-warning text-dark";
                case "info":
                    return "bg-info text-dark";
                default:
                    return "bg-danger";
            }
        }
        return "bg-success";
    }

    let openRows = $state(new Set<string>());

    function rowKey(r: DomainBlacklistSourceResult): string {
        return `${r.source_id}::${r.subject ?? ""}`;
    }

    function toggle(key: string) {
        const next = new Set(openRows);
        if (next.has(key)) {
            next.delete(key);
        } else {
            next.add(key);
        }
        openRows = next;
    }

    function hasDetails(r: DomainBlacklistSourceResult): boolean {
        return (r.reasons?.length ?? 0) > 1 || (r.evidence?.length ?? 0) > 0;
    }

    function firstReason(r: DomainBlacklistSourceResult): string {
        if (r.error) return r.error;
        if (r.reasons && r.reasons.length > 0) return r.reasons[0];
        if (!r.enabled && paidSourceIds.has(r.source_id)) {
            return "API key not configured by the operator";
        }
        if (!r.enabled) return "Source disabled";
        return "—";
    }
</script>

<div class="card shadow-sm mt-4" id="domain-blacklist-details">
    <div class="card-header" class:bg-white={$theme === "light"} class:bg-dark={$theme !== "light"}>
        <h4 class="mb-0">
            <i class="bi bi-shield-shaded me-2"></i>
            Source Verdicts
        </h4>
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-sm table-striped table-hover align-middle mb-0">
                <thead>
                    <tr>
                        <th scope="col" class="text-nowrap">Status</th>
                        <th scope="col">Source</th>
                        <th scope="col">Detail</th>
                        <th scope="col" class="text-end text-nowrap">Links</th>
                    </tr>
                </thead>
                <tbody>
                    {#each sorted as r (rowKey(r))}
                        {@const key = rowKey(r)}
                        {@const open = openRows.has(key)}
                        {@const expandable = hasDetails(r)}
                        <tr class:text-muted={!r.enabled}>
                            <td class="text-nowrap">
                                <span class="badge {statusBadgeClass(r)}">{statusLabel(r)}</span>
                            </td>
                            <td>
                                <div class="fw-semibold">{r.source_name}</div>
                                <small class="text-muted">
                                    <code>{r.source_id}</code>
                                    {#if r.subject}
                                        · <code>{r.subject}</code>
                                    {/if}
                                </small>
                            </td>
                            <td>
                                <span class="detail-text">{firstReason(r)}</span>
                                {#if expandable}
                                    <button
                                        type="button"
                                        class="btn btn-link btn-sm p-0 ms-1 align-baseline"
                                        onclick={() => toggle(key)}
                                        aria-expanded={open}
                                    >
                                        {open ? "Hide details" : "Show details"}
                                    </button>
                                {/if}
                            </td>
                            <td class="text-end text-nowrap">
                                {#if r.lookup_url}
                                    <a
                                        href={r.lookup_url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        class="btn btn-sm btn-outline-secondary"
                                        title="Open lookup page"
                                        aria-label="Open lookup page"
                                    >
                                        <i class="bi bi-box-arrow-up-right"></i>
                                    </a>
                                {/if}
                            </td>
                        </tr>
                        {#if expandable && open}
                            <tr class="detail-row">
                                <td></td>
                                <td colspan="3">
                                    {#if r.reasons && r.reasons.length > 0}
                                        <ul class="small mb-2">
                                            {#each r.reasons as reason}
                                                <li>{reason}</li>
                                            {/each}
                                        </ul>
                                    {/if}
                                    {#if r.evidence && r.evidence.length > 0}
                                        <table
                                            class="table table-sm table-bordered mb-0 evidence-table"
                                        >
                                            <thead>
                                                <tr>
                                                    <th scope="col">Label</th>
                                                    <th scope="col">Value</th>
                                                    <th scope="col">Status</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {#each r.evidence as ev}
                                                    <tr>
                                                        <td class="text-nowrap">{ev.label}</td>
                                                        <td>
                                                            <code class="small">{ev.value}</code>
                                                        </td>
                                                        <td class="text-nowrap">
                                                            {#if ev.status}
                                                                <span
                                                                    class="badge bg-light text-dark"
                                                                    >{ev.status}</span
                                                                >
                                                            {:else}
                                                                <span class="text-muted">—</span>
                                                            {/if}
                                                        </td>
                                                    </tr>
                                                {/each}
                                            </tbody>
                                        </table>
                                    {/if}
                                    {#if r.reference}
                                        <p class="small text-muted mt-2 mb-0">
                                            Reference: {r.reference}
                                        </p>
                                    {/if}
                                </td>
                            </tr>
                        {/if}
                    {/each}
                </tbody>
            </table>
        </div>
    </div>
</div>

<style>
    .detail-text {
        display: inline-block;
        max-width: 100%;
        overflow-wrap: anywhere;
    }

    .detail-row td {
        background-color: rgba(0, 0, 0, 0.025);
    }

    .evidence-table code {
        word-break: break-all;
    }
</style>
