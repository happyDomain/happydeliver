<script lang="ts">
    import { SvelteSet } from "svelte/reactivity";

    import type { DomainBlacklistResult, DomainBlacklistSourceResult } from "#lib/api/types.gen.js";
    import type { SectionStatus } from "#lib/sections.js";
    import ReportSection from "./ReportSection.svelte";

    interface Props {
        blacklist: DomainBlacklistResult;
        // The domain the check was asked about, to tell whether the sources
        // were queried for another, registered, one.
        domain: string;
        /** Defaults to unfolded only when a source lists the domain. */
        open?: boolean;
        class?: string;
    }

    let { blacklist, domain, open, class: className = "mt-4" }: Props = $props();

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

    const openRows = new SvelteSet<string>();

    function rowKey(r: DomainBlacklistSourceResult): string {
        return `${r.source_id}::${r.subject ?? ""}`;
    }

    function toggle(key: string) {
        if (openRows.has(key)) {
            openRows.delete(key);
        } else {
            openRows.add(key);
        }
    }

    function hasDetails(r: DomainBlacklistSourceResult): boolean {
        return (r.reasons?.length ?? 0) > 1 || (r.evidence?.length ?? 0) > 0;
    }

    function plural(n: number, word: string): string {
        return `${n} ${word}${n === 1 ? "" : "s"}`;
    }

    const listed = $derived(
        blacklist.verdict === "listed" || blacklist.verdict === "listed_critical",
    );

    const status: SectionStatus = $derived(
        blacklist.verdict === "listed_critical"
            ? {
                  label: `Listed on ${plural(summary.critical, "critical source")}`,
                  tone: "danger",
                  needsAttention: true,
              }
            : blacklist.verdict === "listed"
              ? {
                    label: `Listed on ${plural(summary.listed, "source")}`,
                    tone: "warning",
                    needsAttention: true,
                }
              : blacklist.verdict === "inconclusive"
                ? { label: "Inconclusive", tone: "muted", needsAttention: false }
                : { label: "Not listed", tone: "success", needsAttention: false },
    );

    // What a source has to say comes first; the sources that saw nothing are folded into a
    // count, as their verdict is the expected one.
    const notable = $derived(
        sorted.filter(
            (r) => r.status === "listed" || r.status === "errored" || r.status === "pending",
        ),
    );
    const quiet = $derived(
        sorted.filter((r) => r.status === "clean" || r.status === "informational"),
    );
</script>

<ReportSection
    id="reputation-details"
    class={className}
    title="Domain Reputation"
    icon="shield-shaded"
    grade={blacklist.grade}
    score={blacklist.score}
    {status}
    open={open ?? listed}
>
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
    {#if notable.length > 0}
        <div class="list-group list-group-flush">
            {#each notable as r (rowKey(r))}
                {@render sourceRow(r)}
            {/each}
        </div>
    {/if}
    {#if quiet.length > 0}
        <div class="card-body py-2" class:border-top={notable.length > 0}>
            <details class="passed-items">
                <summary>
                    <i class="bi bi-check-circle-fill text-success me-1"></i>
                    {plural(quiet.length, "source")} report nothing against this domain
                </summary>
                <div class="list-group list-group-flush mt-2">
                    {#each quiet as r (rowKey(r))}
                        {@render sourceRow(r)}
                    {/each}
                </div>
            </details>
        </div>
    {/if}
</ReportSection>

{#snippet sourceRow(r: DomainBlacklistSourceResult)}
    {@const key = rowKey(r)}
    {@const expanded = openRows.has(key)}
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
                            aria-expanded={expanded}
                        >
                            {expanded ? "Hide details" : "Show details"}
                        </button>
                    {/if}
                </div>
                {#if r.status === "informational"}
                    <div class="small text-muted">
                        Web ad and tracker blocklist, not used by mail filters: not counted in the
                        score.
                    </div>
                {/if}
                {#if expandable && expanded}
                    <div class="mt-2">
                        {#if r.reasons && r.reasons.length > 0}
                            <ul class="small mb-2">
                                {#each r.reasons as reason}
                                    <li>{reason}</li>
                                {/each}
                            </ul>
                        {/if}
                        {#if r.evidence && r.evidence.length > 0}
                            <table class="table table-sm table-bordered mb-0 evidence-table">
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
                                                    <span class="badge bg-light">
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
{/snippet}

<style>
    .evidence-table code {
        word-break: break-all;
    }
</style>
