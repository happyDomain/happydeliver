<script lang="ts">
    import type { DmarcRecord, SpfRecord } from "$lib/api/types.gen";

    interface Props {
        spfRecords?: SpfRecord[];
        dmarcRecord?: DmarcRecord;
    }

    let { spfRecords, dmarcRecord }: Props = $props();

    // Check if DMARC has strict policy (quarantine or reject)
    const dmarcStrict = $derived(
        dmarcRecord?.valid &&
            dmarcRecord?.policy &&
            (dmarcRecord.policy === "quarantine" || dmarcRecord.policy === "reject"),
    );

    // Compute overall validity
    const spfIsValid = $derived(spfRecords?.reduce((acc, r) => acc && r.valid, true) ?? false);
    const spfCanBeImprove = $derived(
        spfRecords &&
            spfRecords.length > 0 &&
            spfRecords.filter((r) => !r.record?.includes(" redirect="))[0]?.all_qualifier != "-" &&
            !dmarcStrict,
    );
</script>

{#if spfRecords && spfRecords.length > 0}
    <div class="card mb-4" id="dns-spf">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="text-muted mb-2">
                <i
                    class="bi"
                    class:bi-check-circle-fill={spfIsValid && !spfCanBeImprove}
                    class:text-success={spfIsValid && !spfCanBeImprove}
                    class:bi-arrow-up-circle-fill={spfIsValid && spfCanBeImprove}
                    class:text-warning={spfIsValid && spfCanBeImprove}
                    class:bi-x-circle-fill={!spfIsValid}
                    class:text-danger={!spfIsValid}
                ></i>
                Sender Policy Framework
            </h5>
            <span class="badge bg-secondary">SPF</span>
        </div>
        <div class="card-body">
            <p class="card-text small text-muted mb-0">
                SPF specifies which mail servers are authorized to send emails on behalf of your
                domain. Receiving servers check the sender's IP address against your SPF record to
                prevent email spoofing.
            </p>
        </div>
        <div class="list-group list-group-flush">
            {#each spfRecords as spf, index}
                <div class="list-group-item">
                    {#if spf.domain}
                        <div class="mb-2">
                            <strong>Domain:</strong> <code>{spf.domain}</code>
                            {#if index > 0}
                                <span class="badge bg-info ms-2">Included</span>
                            {/if}
                        </div>
                    {/if}
                    <div class="mb-2">
                        <strong>Status:</strong>
                        {#if spf.valid}
                            <span class="badge bg-success">Valid</span>
                        {:else}
                            <span class="badge bg-danger">Invalid</span>
                        {/if}
                    </div>
                    {#if spf.all_qualifier}
                        <div class="mb-2">
                            <strong>All Mechanism Policy:</strong>
                            {#if spf.all_qualifier === "-"}
                                <span class="badge bg-success">Strict (-all)</span>
                            {:else if spf.all_qualifier === "~"}
                                <span class="badge bg-warning">Softfail (~all)</span>
                            {:else if spf.all_qualifier === "+"}
                                <span class="badge bg-danger">Pass (+all)</span>
                            {:else if spf.all_qualifier === "?"}
                                <span class="badge bg-warning">Neutral (?all)</span>
                            {/if}
                            {#if index === 0 || (index === 1 && spfRecords[0].record?.includes("redirect="))}
                                <div
                                    class="alert small mt-2"
                                    class:alert-warning={spf.all_qualifier !== "-"}
                                    class:alert-success={spf.all_qualifier === "-"}
                                >
                                    {#if spf.all_qualifier === "-"}
                                        All unauthorized servers will be rejected. This is the
                                        recommended strict policy.
                                    {:else if dmarcStrict}
                                        While your DMARC {dmarcRecord?.policy} policy provides some protection,
                                        consider using <code>-all</code> for better security with some
                                        old mailbox providers.
                                    {:else if spf.all_qualifier === "~"}
                                        Unauthorized servers will softfail. Consider using <code
                                            >-all</code
                                        > for stricter policy, though this rarely affects legitimate
                                        email deliverability.
                                    {:else if spf.all_qualifier === "+"}
                                        All servers are allowed to send email. This severely weakens
                                        email authentication. Use <code>-all</code> for strict policy.
                                    {:else if spf.all_qualifier === "?"}
                                        No statement about unauthorized servers. Use <code
                                            >-all</code
                                        > for strict policy to prevent spoofing.
                                    {/if}
                                </div>
                            {/if}
                        </div>
                    {/if}
                    {#if spf.record}
                        <div class="mb-2">
                            <strong>Record:</strong><br />
                            <code class="d-block mt-1 text-break">{spf.record}</code>
                        </div>
                    {/if}
                    {#if spf.error}
                        <div class="alert alert-{spf.valid ? 'warning' : 'danger'} mb-0 mt-2">
                            <i class="bi bi-{spf.valid ? 'exclamation-triangle' : 'x-circle'} me-1"
                            ></i>
                            <strong>{spf.valid ? "Warning:" : "Error:"}</strong>
                            {spf.error}
                        </div>
                    {/if}
                </div>
            {/each}
        </div>
    </div>
{/if}
