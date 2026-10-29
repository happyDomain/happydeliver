<script lang="ts">
    import type { ReceivedHop } from "#lib/api/types.gen.js";
    import ReportSection from "./ReportSection.svelte";

    interface Props {
        receivedChain: ReceivedHop[];
        /** The path is context, not a grade: folded unless asked otherwise. */
        open?: boolean;
    }

    let { receivedChain, open = false }: Props = $props();

    // Hops above the inbound one are the recipient's own. -1 when the backend
    // flagged none, which marks nothing.
    const entryIndex = $derived(receivedChain.findIndex((hop) => hop.inbound));

    // Mirror of the backend protocolIndicatesTLS (RFC 3848): the transport keyword
    // gains a trailing "S" when TLS was used (ESMTPS, ESMTPSA, SMTPS, LMTPS, LMTPSA...).
    function protocolIndicatesTLS(withProto: string | undefined | null): boolean {
        if (!withProto) return false;
        const p = withProto.trim().toUpperCase();
        return p.endsWith("S") || p.endsWith("SA");
    }

    // RFC 3848: a trailing "A" means the sender authenticated (SMTP AUTH):
    // ESMTPA, ESMTPSA, LMTPA, LMTPSA...
    function protocolIndicatesAuth(withProto: string | undefined | null): boolean {
        if (!withProto) return false;
        return withProto.trim().toUpperCase().endsWith("A");
    }

    // What the folded header says: how many relays the message crossed, and how many of the
    // connections are known to have been encrypted.
    const encrypted = $derived(
        receivedChain.filter((hop) => hop.tls || protocolIndicatesTLS(hop.with)).length,
    );

    const pathStatus = $derived({
        label: `${receivedChain.length} hop${receivedChain.length > 1 ? "s" : ""}, ${encrypted} with TLS`,
        tone: "muted" as const,
        needsAttention: false,
    });
</script>

{#if receivedChain && receivedChain.length > 0}
    <ReportSection id="email-path" title="Email Path" icon="pin-map" status={pathStatus} {open}>
        <div class="list-group list-group-flush">
            {#each receivedChain as hop, i (i)}
                <div class="list-group-item" class:bg-light={i < entryIndex}>
                    <div class="d-flex w-100 justify-content-between">
                        <h6 class="mb-1">
                            <span class="badge bg-primary me-2">{receivedChain.length - i}</span>
                            {#if i < entryIndex}
                                <span class="badge bg-secondary me-2">Internal</span>
                            {/if}
                            {hop.reverse || "-"}
                            {#if hop.ip}<span class="text-muted">({hop.ip})</span>{/if} → {hop.by ||
                                "Unknown"}
                        </h6>
                        <small class="text-muted" title={hop.timestamp}>
                            {hop.timestamp
                                ? new Intl.DateTimeFormat("default", {
                                      dateStyle: "long",
                                      timeStyle: "short",
                                  }).format(new Date(hop.timestamp))
                                : "-"}
                        </small>
                    </div>
                    {#if hop.with || hop.id || hop.from}
                        <p class="mb-1 small d-flex gap-3">
                            {#if hop.with}
                                <span>
                                    <span class="text-muted">Protocol:</span>
                                    <code>{hop.with}</code>
                                </span>
                            {/if}
                            {#if hop.id}
                                <span>
                                    <span class="text-muted">ID:</span> <code>{hop.id}</code>
                                </span>
                            {/if}
                            {#if hop.from}
                                <span>
                                    <span class="text-muted">Helo:</span> <code>{hop.from}</code>
                                </span>
                            {/if}
                        </p>
                    {/if}
                    <p class="mb-0 small d-flex flex-wrap align-items-center gap-3">
                        {#if hop.tls}
                            <span class="badge bg-success">
                                <i class="bi bi-lock-fill me-1"></i>TLS
                            </span>
                            {#if hop.tls.version}
                                <span>
                                    <span class="text-muted">Version:</span>
                                    <code>{hop.tls.version}</code>
                                </span>
                            {/if}
                            {#if hop.tls.cipher}
                                <span>
                                    <span class="text-muted">Cipher:</span>
                                    <code>{hop.tls.cipher}</code>
                                </span>
                            {/if}
                            {#if hop.tls.bits}
                                <span>
                                    <span class="text-muted">Strength:</span>
                                    <code>{hop.tls.bits} bits</code>
                                </span>
                            {/if}
                            {#if hop.tls.verified !== undefined}
                                <span
                                    class:text-success={hop.tls.verified}
                                    class:text-warning={!hop.tls.verified}
                                >
                                    <i
                                        class="bi {hop.tls.verified
                                            ? 'bi-patch-check-fill'
                                            : 'bi-patch-exclamation-fill'} me-1"
                                    ></i>
                                    {hop.tls.verified
                                        ? "Certificate trusted"
                                        : "Certificate not trusted"}
                                </span>
                            {/if}
                        {:else if protocolIndicatesTLS(hop.with)}
                            <span class="badge bg-success">
                                <i class="bi bi-lock-fill me-1"></i>TLS
                            </span>
                        {:else if hop.with}
                            <span class="badge bg-secondary">
                                <i class="bi bi-unlock me-1"></i>No TLS
                            </span>
                        {:else}
                            <span class="badge bg-light text-muted border">
                                <i class="bi bi-question-circle me-1"></i>TLS unknown
                            </span>
                        {/if}
                        {#if protocolIndicatesAuth(hop.with)}
                            <span class="badge bg-info">
                                <i class="bi bi-person-check-fill me-1"></i>Authenticated
                            </span>
                        {/if}
                    </p>
                </div>
            {/each}
        </div>
    </ReportSection>
{/if}
