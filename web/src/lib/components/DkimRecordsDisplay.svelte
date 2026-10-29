<script lang="ts">
    import type { DkimRecord } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        dkimRecords?: DkimRecord[];
    }

    let { dkimRecords }: Props = $props();

    // Compute overall validity
    const dkimIsValid = $derived(dkimRecords?.reduce((acc, r) => acc && r.valid, true) ?? false);

    const dkimSummary = $derived(
        dkimRecords && dkimRecords.length > 0
            ? dkimRecords
                  .map(
                      (r) =>
                          `${r.selector}._domainkey.${r.domain}${r.key_size ? ` (${r.key_size}-bit ${r.key_type ?? "rsa"})` : ""}`,
                  )
                  .join(", ")
            : "No DKIM signature found",
    );
</script>

<CheckCard
    id="dns-dkim"
    title="DomainKeys Identified Mail"
    tag="DKIM"
    status={dkimIsValid ? "pass" : "fail"}
    summary={dkimSummary}
    docs={[docs.dkim, docs.dkimKeySize]}
>
    <div class="card-body">
        <p class="card-text small text-muted mb-0">
            DKIM cryptographically signs your emails, proving they haven't been tampered with in
            transit. Receiving servers verify this signature against your DNS records.
        </p>
    </div>
    <div class="list-group list-group-flush">
        {#if dkimRecords && dkimRecords.length > 0}
            {#each dkimRecords as dkim, i (dkim.selector + "-" + dkim.domain + "-" + i)}
                <div class="list-group-item">
                    <div class="mb-2">
                        <strong>Selector:</strong> <code>{dkim.selector}</code>
                        <strong class="ms-3">Domain:</strong> <code>{dkim.domain}</code>
                    </div>
                    <div class="mb-2">
                        <strong>Status:</strong>
                        {#if dkim.valid}
                            <span class="badge bg-success">Valid</span>
                        {:else}
                            <span class="badge bg-danger">Invalid</span>
                        {/if}
                    </div>
                    {#if dkim.record}
                        <div class="mb-2">
                            <strong>Record:</strong><br />
                            <code class="d-block mt-1 text-break small text-truncate"
                                >{dkim.record}</code
                            >
                        </div>
                    {/if}
                    {#if dkim.error}
                        <div class="text-danger">
                            <strong>Error:</strong>
                            {dkim.error}
                        </div>
                    {/if}
                </div>
            {/each}
        {:else}
            <div class="list-group-item text-muted">
                <i class="bi bi-exclamation-octagon me-2"></i>
                No DKIM signatures found in this email. DKIM provides cryptographic authentication and
                helps avoid spoofing, thus improving deliverability.
            </div>
        {/if}
    </div>
</CheckCard>
