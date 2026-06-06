<script lang="ts">
    interface Props {
        heloHostname?: string;
        ptrRecords?: string[];
        heloPtrMatch?: boolean;
    }

    let { heloHostname, ptrRecords, heloPtrMatch }: Props = $props();

    const normalize = (host: string) => host.replace(/\.$/, "").trim().toLowerCase();

    // Local comparison, identical to the per-record badge logic below, so the
    // summary alert can never contradict the individual "Match" badges.
    const localMatch = $derived(
        !!heloHostname &&
            !!ptrRecords &&
            ptrRecords.some((ptr) => normalize(heloHostname) === normalize(ptr)),
    );

    // Prefer the backend verdict when it is present; otherwise fall back to the
    // local comparison (e.g. for results produced before helo_ptr_match existed).
    const isMatch = $derived(heloPtrMatch ?? localMatch);
</script>

{#if heloHostname}
    <div class="card mb-4">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="text-muted mb-0">
                <i
                    class="bi"
                    class:bi-check-circle-fill={isMatch}
                    class:text-success={isMatch}
                    class:bi-x-circle-fill={!isMatch}
                    class:text-danger={!isMatch}
                ></i>
                HELO / PTR Consistency
            </h5>
            <span class="badge bg-secondary">HELO</span>
        </div>
        <div class="card-body">
            <p class="card-text small text-muted mb-0">
                The HELO/EHLO hostname is the name the sending server announces when it connects.
                Many mail servers check that this name matches the sender IP's reverse DNS (PTR)
                record. A mismatch is a common spam signal and can hurt deliverability.
            </p>
            <div class="mt-2">
                <strong>Announced HELO:</strong> <code>{heloHostname}</code>
            </div>
            {#if ptrRecords && ptrRecords.length > 0}
                <div class="mt-1">
                    <strong>PTR Hostname(s):</strong>
                    {#each ptrRecords as ptr}
                        <div class="d-flex gap-2 align-items-center mt-1">
                            {#if normalize(heloHostname) === normalize(ptr)}
                                <span class="badge bg-success">Match</span>
                            {:else}
                                <span class="badge bg-secondary">Different</span>
                            {/if}
                            <code>{ptr}</code>
                        </div>
                    {/each}
                </div>
            {/if}
        </div>
        {#if !isMatch}
            <div class="list-group list-group-flush">
                <div class="list-group-item">
                    <div class="alert alert-warning mb-0">
                        <i class="bi bi-exclamation-triangle me-1"></i>
                        <strong>Warning:</strong> The announced HELO hostname
                        <code>{heloHostname}</code>
                        {#if ptrRecords && ptrRecords.length > 0}
                            does not match the sender's PTR record{ptrRecords.length > 1 ? "s" : ""}
                            ({#each ptrRecords as ptr, i}<code>{ptr}</code>{i <
                                ptrRecords.length - 1
                                    ? ", "
                                    : ""}{/each}).
                        {:else}
                            could not be matched against a PTR record.
                        {/if}
                        Configuring the HELO name to match reverse DNS improves deliverability.
                    </div>
                </div>
            </div>
        {/if}
    </div>
{/if}
