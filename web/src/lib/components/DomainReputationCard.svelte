<script lang="ts">
    import type { DomainBlacklistResult, DomainBlacklistSourceResult } from "$lib/api/types.gen";
    import { getScoreColorClass } from "$lib/score";
    import { theme } from "$lib/stores/theme";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        blacklist: DomainBlacklistResult;
        // The domain the check was asked about, to tell whether the sources
        // were queried for another, registered, one.
        domain: string;
    }

    let { blacklist, domain }: Props = $props();

    // The backend decides the verdict; the counts shown here are derived
    // from the same results array it renders below, so they cannot diverge.
    let summary = $derived({
        answered: blacklist.results.filter((r) => r.status === "clean" || r.status === "listed")
            .length,
        errored: blacklist.results.filter((r) => r.status === "errored").length,
        pending: blacklist.results.filter((r) => r.status === "pending").length,
        listed: blacklist.results.filter((r) => r.status === "listed").length,
        critical: blacklist.results.filter((r) => r.status === "listed" && r.severity === "crit")
            .length,
        // The backend only sends the sources enabled on this instance.
        enabled: blacklist.results.length,
    });

    type Status = DomainBlacklistSourceResult["status"];

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

    // The backend says how each source counts toward the verdict; the card
    // only orders and labels them.
    function statusRank(status: Status): number {
        switch (status) {
            case "listed":
                return 0;
            case "errored":
                return 1;
            case "pending":
                return 2;
            case "clean":
                return 3;
            case "informational":
                return 4;
        }
    }

    let sorted = $derived(
        [...blacklist.results].sort((a, b) => {
            const ra = statusRank(a.status);
            const rb = statusRank(b.status);
            if (ra !== rb) return ra - rb;
            if (a.status === "listed") {
                const r = severityRank(a.severity) - severityRank(b.severity);
                if (r !== 0) return r;
            }
            return a.source_name.localeCompare(b.source_name);
        }),
    );

    function statusLabel(r: DomainBlacklistSourceResult): string {
        switch (r.status) {
            case "errored":
                return r.blocked_query ? "Resolver blocked" : "Error";
            case "pending":
                return "Pending";
            case "listed":
                return r.severity && r.severity !== "ok" ? `Listed (${r.severity})` : "Listed";
            case "clean":
                return "Clean";
            case "informational":
                return r.listed ? "Listed (web only)" : "Clean";
        }
    }

    function statusClass(r: DomainBlacklistSourceResult): string {
        switch (r.status) {
            case "errored":
                return "text-body";
            case "pending":
                return "text-muted";
            case "listed":
                return r.severity === "warn" || r.severity === "info"
                    ? "text-warning"
                    : "text-danger";
            case "clean":
                return "text-success";
            case "informational":
                return r.listed ? "text-info" : "text-success";
        }
    }

    function statusIcon(r: DomainBlacklistSourceResult): string {
        switch (r.status) {
            case "errored":
                return "bi-exclamation-circle-fill";
            case "pending":
                return "bi-hourglass-split";
            case "listed":
                return "bi-x-circle-fill";
            case "clean":
                return "bi-check-circle-fill";
            case "informational":
                return r.listed ? "bi-info-circle-fill" : "bi-check-circle-fill";
        }
    }

    function firstReason(r: DomainBlacklistSourceResult): string {
        if (r.error) return r.error;
        if (r.reasons && r.reasons.length > 0) return r.reasons[0];
        if (r.blocked_query) {
            return "This list refuses queries from the instance's resolver; result unreliable";
        }
        if (r.status === "pending")
            return "Source data still loading, result available at next check";
        return "—";
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

    function plural(n: number, word: string): string {
        return `${n} ${word}${n === 1 ? "" : "s"}`;
    }
</script>

<div class="card shadow-sm mt-4" id="reputation-details">
    <div class="card-header {$theme === 'light' ? 'bg-white' : 'bg-dark'}">
        <h4 class="mb-0 d-flex justify-content-between align-items-center">
            <span>
                <i class="bi bi-shield-shaded me-2"></i>
                Domain Reputation
            </span>
            <span>
                {#if blacklist.score !== undefined}
                    <span class="badge bg-{getScoreColorClass(blacklist.score)}">
                        {blacklist.score}%
                    </span>
                {/if}
                {#if blacklist.grade !== undefined}
                    <GradeDisplay grade={blacklist.grade} size="small" />
                {/if}
            </span>
        </h4>
    </div>
    {#if blacklist.registered_domain && blacklist.registered_domain !== domain}
        <div class="card-body border-bottom py-2">
            <p class="mb-0 small text-muted">
                <i class="bi bi-info-circle me-2"></i>
                Registered domain: <code>{blacklist.registered_domain}</code>
            </p>
        </div>
    {/if}
    <div class="card-body border-bottom">
        {#if blacklist.verdict === "listed_critical"}
            <div class="alert alert-danger mb-0">
                <p class="mb-0 mt-1 small">
                    <strong>Listed on {plural(summary.critical, "high-severity source")}.</strong>
                    This domain is reported by sources flagged <em>critical</em>. Take action to
                    delist.
                </p>
            </div>
        {:else if blacklist.verdict === "listed"}
            <div class="alert alert-warning mb-0">
                <p class="mb-0 mt-1 small">
                    <strong>Listed on {plural(summary.listed, "source")}.</strong>
                    Listed without critical severity — review the source verdicts below.
                </p>
            </div>
        {:else if blacklist.verdict === "inconclusive"}
            <div class="alert alert-secondary mb-0">
                <p class="mb-0 mt-1 small">
                    <strong>Inconclusive.</strong>
                    {#if summary.enabled === 0}
                        No source is enabled on this instance.
                    {:else if summary.pending > 0}
                        No enabled source answered: {plural(summary.pending, "source")} still loading
                        data, try again in a few minutes.
                    {:else}
                        All enabled sources failed or had their query blocked by the resolver. Try
                        again later.
                    {/if}
                </p>
            </div>
        {:else}
            <div class="alert alert-success mb-0">
                <p class="mb-0 mt-1 small">
                    <strong>No source reports this domain.</strong>
                    No listing among the {plural(summary.answered, "source")} that answered
                    {#if summary.errored > 0 || summary.pending > 0}
                        ({[
                            summary.errored > 0 ? `${summary.errored} errored` : "",
                            summary.pending > 0 ? `${summary.pending} pending` : "",
                        ]
                            .filter(Boolean)
                            .join(", ")}){/if}.
                </p>
            </div>
        {/if}
    </div>
    <div class="list-group list-group-flush">
        {#each sorted as r (rowKey(r))}
            {@const key = rowKey(r)}
            {@const open = openRows.has(key)}
            {@const expandable = hasDetails(r)}
            <div class="list-group-item">
                <div class="d-flex align-items-start">
                    <i class="bi {statusIcon(r)} {statusClass(r)} me-2 fs-5"></i>
                    <div class="flex-grow-1">
                        <strong>{r.source_name}</strong>
                        <span class="text-uppercase ms-2 {statusClass(r)}">
                            {statusLabel(r)}
                        </span>
                        {#if r.lookup_url}
                            <a
                                href={r.lookup_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                class="btn btn-sm btn-outline-secondary float-end"
                                title="Open lookup page"
                                aria-label="Open lookup page"
                            >
                                <i class="bi bi-box-arrow-up-right"></i>
                            </a>
                        {/if}
                        <div class="small text-muted">
                            <code>{r.source_id}</code>
                            {#if r.subject}
                                &middot; <code>{r.subject}</code>
                            {/if}
                        </div>
                        <div class="small">
                            {firstReason(r)}
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
                        </div>
                        {#if r.status === "informational"}
                            <div class="small text-muted">
                                Web ad and tracker blocklist, not used by mail filters: not counted
                                in the score.
                            </div>
                        {/if}
                        {#if expandable && open}
                            <div class="mt-2">
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
                                                            <span class="badge bg-light text-dark">
                                                                {ev.status}
                                                            </span>
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
                            </div>
                        {/if}
                    </div>
                </div>
            </div>
        {/each}
    </div>
</div>

<style>
    .evidence-table code {
        word-break: break-all;
    }
</style>
