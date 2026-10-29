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

    // The chain is newest first, as the Received headers stack up. The path reads the way
    // the message travelled: sender first, delivery last. Each hop keeps its chain index.
    const hops = $derived(receivedChain.map((hop, index) => ({ hop, index })).reverse());

    function toMs(timestamp: string | undefined): number | undefined {
        if (!timestamp) return undefined;
        const ms = new Date(timestamp).getTime();
        return Number.isNaN(ms) ? undefined : ms;
    }

    // Time spent since the message left the first hop: ms below a second, then s, min, h.
    function formatElapsed(ms: number): string {
        if (ms < 1000) return `${Math.max(0, Math.round(ms))} ms`;
        const s = Math.round(ms / 1000);
        if (s < 60) return `${s} s`;
        const m = Math.floor(s / 60);
        if (m < 60) return `${m} min${s % 60 ? ` ${s % 60} s` : ""}`;
        const h = Math.floor(m / 60);
        return `${h} h${m % 60 ? ` ${m % 60} min` : ""}`;
    }

    const startMs = $derived(hops.map((h) => toMs(h.hop.timestamp)).find((t) => t !== undefined));

    function elapsed(timestamp: string | undefined): string | undefined {
        const t = toMs(timestamp);
        return t === undefined || startMs === undefined ? undefined : formatElapsed(t - startMs);
    }

    const dateFormat = new Intl.DateTimeFormat("default", {
        dateStyle: "medium",
        timeStyle: "medium",
    });

    const pathStatus = $derived({
        label: `${receivedChain.length} hop${receivedChain.length > 1 ? "s" : ""}, ${encrypted} with TLS`,
        tone: "muted" as const,
        needsAttention: false,
    });
</script>

{#if receivedChain && receivedChain.length > 0}
    <ReportSection id="email-path" title="Email Path" icon="pin-map" status={pathStatus} {open}>
        <ol class="hops">
            {#each hops as { hop, index }, n (index)}
                {@const last = n === hops.length - 1}
                {@const internal = index < entryIndex}
                {@const tls = hop.tls || protocolIndicatesTLS(hop.with)}
                {@const time = elapsed(hop.timestamp)}
                <li class="hop" class:last class:internal class:entry={hop.inbound}>
                    <span class="node" aria-hidden="true"></span>
                    <div class="hop-main">
                        <div
                            class="hop-name d-flex flex-wrap align-items-center gap-2 font-monospace fw-semibold text-break"
                        >
                            {hop.by || "Unknown"}
                            {#if hop.inbound}
                                <span
                                    class="badge text-primary-emphasis bg-primary-subtle border border-primary-subtle"
                                    >Entry into recipient</span
                                >
                            {:else if internal}
                                <span class="badge text-body-secondary bg-body-secondary border"
                                    >Internal</span
                                >
                            {/if}
                            {#if last}
                                <span
                                    class="badge text-success-emphasis bg-success-subtle border border-success-subtle"
                                    >Delivered</span
                                >
                            {/if}
                        </div>
                        <div class="hop-meta">
                            <span>
                                <span class="label">from</span>
                                {#if hop.reverse || hop.from}<span class="font-monospace"
                                        >{hop.reverse || hop.from}</span
                                    >{/if}
                                {#if hop.ip}
                                    {#if hop.reverse || hop.from}(<span class="font-monospace"
                                            >{hop.ip}</span
                                        >){:else}<span class="font-monospace">{hop.ip}</span>{/if}
                                {:else if !hop.reverse && !hop.from}-{/if}
                            </span>
                            {#if hop.from && hop.from !== hop.reverse}
                                <span><span class="label">helo</span> <code>{hop.from}</code></span>
                            {/if}
                            {#if hop.with}
                                <span><span class="label">via</span> <code>{hop.with}</code></span>
                            {/if}
                            {#if hop.id}
                                <span><span class="label">id</span> <code>{hop.id}</code></span>
                            {/if}
                        </div>
                        {#if hop.tls && (hop.tls.cipher || hop.tls.bits)}
                            <div class="hop-meta">
                                {#if hop.tls.cipher}
                                    <span
                                        ><span class="label">cipher</span>
                                        <code>{hop.tls.cipher}</code></span
                                    >
                                {/if}
                                {#if hop.tls.bits}
                                    <span
                                        ><span class="label">strength</span>
                                        <code>{hop.tls.bits} bits</code></span
                                    >
                                {/if}
                            </div>
                        {/if}
                    </div>
                    <div class="d-flex flex-column align-items-end gap-1 ms-auto text-end">
                        <span class="font-monospace" title={hop.timestamp}>{time ?? "-"}</span>
                        {#if hop.timestamp && toMs(hop.timestamp) !== undefined}
                            <small class="text-body-secondary"
                                >{dateFormat.format(new Date(hop.timestamp))}</small
                            >
                        {/if}
                        <span class="d-flex flex-wrap justify-content-end gap-1">
                            {#if tls}
                                <span
                                    class="badge rounded-pill border text-success-emphasis bg-success-subtle border-success-subtle"
                                >
                                    <i class="bi bi-lock-fill me-1"></i>{hop.tls?.version || "TLS"}
                                </span>
                            {:else if hop.with}
                                <span
                                    class="badge rounded-pill border text-body-secondary bg-body-secondary"
                                >
                                    <i class="bi bi-unlock me-1"></i>No TLS
                                </span>
                            {:else}
                                <span class="badge rounded-pill border text-body-secondary">
                                    <i class="bi bi-question-circle me-1"></i>TLS unknown
                                </span>
                            {/if}
                            {#if hop.tls?.verified !== undefined}
                                <span
                                    class="badge rounded-pill border {hop.tls.verified
                                        ? 'text-success-emphasis bg-success-subtle border-success-subtle'
                                        : 'text-warning-emphasis bg-warning-subtle border-warning-subtle'}"
                                >
                                    <i
                                        class="bi {hop.tls.verified
                                            ? 'bi-patch-check-fill'
                                            : 'bi-patch-exclamation-fill'} me-1"
                                    ></i>{hop.tls.verified ? "Trusted cert" : "Untrusted cert"}
                                </span>
                            {/if}
                            {#if protocolIndicatesAuth(hop.with)}
                                <span
                                    class="badge rounded-pill border text-info-emphasis bg-info-subtle border-info-subtle"
                                >
                                    <i class="bi bi-person-check-fill me-1"></i>Authenticated
                                </span>
                            {/if}
                        </span>
                    </div>
                </li>
            {/each}
        </ol>
    </ReportSection>
{/if}

<style>
    /* The path as a timeline: a rail down the left, a node on it for each hop. */
    .hops {
        --rail: var(--bs-border-color);
        margin: 0;
        padding: 0.5rem 1.5rem;
        list-style: none;
    }

    .hop {
        position: relative;
        display: flex;
        flex-wrap: wrap;
        justify-content: space-between;
        gap: 0.25rem 1rem;
        padding: 0.875rem 0 0.875rem 1.75rem;

        /* The separator starts past the rail, so it doesn't cross it. It hangs
           off .hop-main, positioned against the hop: the hop's own ::after is
           the chevron. */
        & + .hop > .hop-main::before {
            content: "";
            position: absolute;
            left: 1.75rem;
            right: 0;
            top: 0;
            border-top: 1px solid var(--bs-border-color-translucent);
        }

        /* The rail runs from node to node: it starts at the first and stops at the last */
        &::before {
            content: "";
            position: absolute;
            left: 0.4375rem;
            top: 0;
            bottom: 0;
            width: 1px;
            background: var(--rail);
        }

        &:first-child::before {
            top: 1.5rem;
        }

        &.last::before {
            bottom: calc(100% - 1.5rem);
        }

        &:only-child::before {
            display: none;
        }

        /* A chevron halfway along the rail to the next hop, pointing the way the message went.
           The nodes sit 1.5rem under the top of their row, so the middle of the segment is
           1.5rem under the middle of this one. */
        &:not(.last)::after {
            content: "";
            position: absolute;
            left: 0.46875rem;
            top: calc(50% + 1.5rem);
            width: 0.75rem;
            height: 0.75rem;
            transform: translate(-50%, -50%);
            background-color: var(--bs-secondary-color);
            mask: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'%3E%3Cpath d='M2 4l4 4 4-4' fill='none' stroke='black' stroke-width='1.75' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E")
                center / contain no-repeat;
        }
    }

    .node {
        position: absolute;
        left: 0;
        top: 1.1875rem;
        z-index: 1;
        width: 0.9375rem;
        height: 0.9375rem;
        box-sizing: border-box;
        border: 2px solid var(--rail);
        border-radius: 50%;
        background: var(--bs-body-bg);

        .entry & {
            border-color: var(--bs-primary);
        }

        .last & {
            border-color: var(--bs-success);
            background: var(--bs-success);
        }
    }

    .internal .hop-name {
        color: var(--bs-secondary-color);
    }

    .hop-main {
        flex: 1 1 18rem;
        min-width: 0;
    }

    .hop-meta {
        display: flex;
        flex-wrap: wrap;
        gap: 0 0.75rem;
        margin-top: 0.125rem;
        font-size: 0.8125rem;
        color: var(--bs-secondary-color);
        overflow-wrap: anywhere;

        code {
            color: inherit;
            font-size: inherit;
        }

        .label {
            opacity: 0.7;
        }
    }
</style>
