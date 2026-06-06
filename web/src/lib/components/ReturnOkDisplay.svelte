<script lang="ts">
    import type { SchemasReturnOk, SchemasReturnOkDomain } from "$lib/api/types.gen";

    interface Props {
        returnOk?: SchemasReturnOk;
    }

    let { returnOk }: Props = $props();

    type Row = { label: string; entry: SchemasReturnOkDomain };

    const rows = $derived<Row[]>(
        [
            returnOk?.from ? { label: "From", entry: returnOk.from } : undefined,
            returnOk?.return_path
                ? { label: "Return-Path", entry: returnOk.return_path }
                : undefined,
        ].filter((r): r is Row => r !== undefined),
    );

    const hasFail = $derived(rows.some((r) => r.entry.status === "fail"));
    const hasWarn = $derived(rows.some((r) => r.entry.status === "warn"));
    const allPass = $derived(rows.length > 0 && rows.every((r) => r.entry.status === "pass"));

    // Header icon reflects the worst status across the checked domains.
    const headerOk = $derived(allPass);

    function badgeClass(status: string): string {
        if (status === "pass") return "bg-success";
        if (status === "warn") return "bg-warning text-dark";
        return "bg-danger";
    }

    function badgeLabel(status: string): string {
        if (status === "pass") return "MX";
        if (status === "warn") return "A/AAAA only";
        return "Unreachable";
    }
</script>

{#if rows.length > 0}
    <div class="card mb-4">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="text-muted mb-0">
                <i
                    class="bi"
                    class:bi-check-circle-fill={headerOk}
                    class:text-success={headerOk}
                    class:bi-exclamation-triangle-fill={!headerOk && !hasFail}
                    class:text-warning={!headerOk && !hasFail}
                    class:bi-x-circle-fill={hasFail}
                    class:text-danger={hasFail}
                ></i>
                Return Address Reachability
            </h5>
            <span class="badge bg-secondary">RETURN-OK</span>
        </div>
        <div class="card-body">
            <p class="card-text small text-muted mb-0">
                Replies (to the From address) and bounces (to the Return-Path) can only be delivered
                if the sender's domains accept mail. A domain should publish MX records; an A/AAAA
                record works as an implicit fallback but is not recommended. A domain with neither
                is unreachable and silently drops replies and bounces.
            </p>
        </div>
        <div class="list-group list-group-flush">
            {#each rows as { label, entry } (label)}
                <div class="list-group-item">
                    <div class="d-flex align-items-center gap-2 flex-wrap">
                        <span class="text-muted" style="min-width: 6.5rem">{label} domain:</span>
                        <code>{entry.domain}</code>
                        <span class="badge {badgeClass(entry.status)}">
                            {badgeLabel(entry.status)}
                        </span>
                        {#if entry.org_domain}
                            <small class="text-muted">
                                via organizational domain <code>{entry.org_domain}</code>
                            </small>
                        {/if}
                    </div>
                </div>
            {/each}
        </div>
        {#if hasFail || hasWarn}
        <div class="list-group list-group-flush">
            <div class="list-group-item">
                {#if hasFail}
                    <div class="alert alert-danger mb-0">
                        <i class="bi bi-x-circle me-1"></i>
                        <strong>Error:</strong> At least one sender domain has no MX and no A/AAAA record.
                        Replies or bounce messages to that domain will be lost. Publish an MX record pointing
                        to a mail server that accepts mail.
                    </div>
                {:else if hasWarn}
                    <div class="alert alert-warning mb-0">
                        <i class="bi bi-exclamation-triangle me-1"></i>
                        <strong>Warning:</strong> A sender domain has no MX record and relies on its A/AAAA
                        record (implicit MX). Mail is still deliverable, but publishing an explicit MX
                        record is recommended.
                    </div>
                {/if}
            </div>
        </div>
        {/if}
    </div>
{/if}
