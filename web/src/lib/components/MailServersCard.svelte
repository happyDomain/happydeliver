<script lang="ts">
    import type { MailServerEndpoint, MailServersResult } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import { compareBySeverity } from "#lib/issues.js";
    import type { SectionStatus } from "#lib/sections.js";
    import DocLinks from "./DocLinks.svelte";
    import IssueNote from "./IssueNote.svelte";
    import ReportSection from "./ReportSection.svelte";
    import TileLoader from "./TileLoader.svelte";

    interface Props {
        result?: MailServersResult | null;
        loading?: boolean;
        error?: string | null;
        class?: string;
    }

    let { result, loading = false, error, class: className = "mt-4" }: Props = $props();

    const issues = $derived([...(result?.issues ?? [])].sort(compareBySeverity));
    const actionable = $derived(issues.filter((i) => i.severity !== "info"));

    const status: SectionStatus | undefined = $derived.by(() => {
        if (loading) return { label: "Probing…", tone: "muted", needsAttention: false };
        if (!result) return undefined;
        switch (result.status) {
            case "inconclusive":
                return { label: "Inconclusive", tone: "muted", needsAttention: false };
            case "null_mx":
                return { label: "Accepts no mail (null MX)", tone: "info", needsAttention: false };
            case "no_mx":
                return { label: "No server to deliver to", tone: "danger", needsAttention: true };
        }
        const critical = actionable.filter(
            (i) => i.severity === "critical" || i.severity === "high",
        ).length;
        if (critical > 0)
            return {
                label: `${critical} problem${critical > 1 ? "s" : ""} to fix`,
                tone: "danger",
                needsAttention: true,
            };
        if (actionable.length > 0)
            return {
                label: `${actionable.length} thing${actionable.length > 1 ? "s" : ""} to improve`,
                tone: "warning",
                needsAttention: true,
            };
        return { label: "All servers answer correctly", tone: "success", needsAttention: false };
    });

    type Pill = "ok" | "fail" | "warn" | "none";

    interface Step {
        label: string;
        title: string;
        state: (ep: MailServerEndpoint) => Pill;
        detail?: (ep: MailServerEndpoint) => string | undefined;
    }

    const bool = (v: boolean | undefined, ran = true): Pill =>
        !ran || v === undefined ? "none" : v ? "ok" : "fail";

    const steps: Step[] = [
        {
            label: "TCP",
            title: "Connection on port 25",
            state: (ep) => bool(ep.tcp_connected, ep.probed),
            detail: (ep) => (ep.latency_ms !== undefined ? `${ep.latency_ms} ms` : undefined),
        },
        {
            label: "220",
            title: "SMTP greeting",
            state: (ep) => (ep.tcp_connected ? (ep.banner ? "ok" : "fail") : "none"),
            detail: (ep) => ep.banner,
        },
        {
            label: "EHLO",
            title: "EHLO accepted",
            state: (ep) =>
                ep.ehlo === undefined || !ep.banner
                    ? "none"
                    : ep.ehlo_fallback_helo
                      ? "warn"
                      : bool(ep.ehlo),
            detail: (ep) => ep.ehlo_hostname,
        },
        {
            label: "STARTTLS",
            title: "TLS negotiated",
            state: (ep) =>
                !ep.ehlo ? "none" : ep.auth_before_tls?.length ? "fail" : bool(ep.starttls),
            detail: (ep) =>
                ep.auth_before_tls?.length
                    ? `AUTH ${ep.auth_before_tls.join(" ")} offered in clear`
                    : [ep.tls_version, ep.tls_cipher].filter(Boolean).join(", ") || undefined,
        },
        {
            label: "Cert",
            title: "Certificate valid for the MX name",
            state: (ep) => {
                const c = ep.certificate;
                if (!ep.starttls || !c) return "none";
                if (!c.chain_valid || !c.hostname_match || (c.days_left ?? 0) < 0) return "fail";
                return (c.days_left ?? 99) < 14 ? "warn" : "ok";
            },
            detail: (ep) => {
                const c = ep.certificate;
                if (!c) return undefined;
                if (c.chain_error) return c.chain_error;
                return [
                    c.issuer ? `issued by ${c.issuer}` : "",
                    c.days_left !== undefined ? `expires in ${c.days_left} days` : "",
                ]
                    .filter(Boolean)
                    .join(", ");
            },
        },
        {
            label: "DANE",
            title: "Certificate matches the TLSA records",
            state: (ep) =>
                ep.dane === "match"
                    ? "ok"
                    : ep.dane === "mismatch"
                      ? "fail"
                      : ep.dane === "unverified"
                        ? "warn"
                        : "none",
            detail: (ep) => ep.dane_message,
        },
        {
            label: "<>",
            title: "Bounces (MAIL FROM:<>) accepted",
            state: (ep) => bool(ep.null_sender_accepted, ep.ehlo),
            detail: (ep) => ep.null_sender_response,
        },
        {
            label: "postmaster",
            title: "Mail to postmaster@ accepted",
            state: (ep) => bool(ep.postmaster_accepted, ep.ehlo),
            detail: (ep) => ep.postmaster_response,
        },
        {
            label: "Relay",
            title: "Refuses to relay to other domains",
            state: (ep) => (ep.open_relay === undefined ? "none" : ep.open_relay ? "fail" : "ok"),
            detail: (ep) => ep.open_relay_response,
        },
        {
            label: "rDNS",
            title: "Reverse DNS confirmed forward",
            state: (ep) => (!ep.probed ? "none" : !ep.ptr ? "fail" : ep.fcrdns ? "ok" : "warn"),
            detail: (ep) => ep.ptr,
        },
    ];

    const pillClass: Record<Pill, string> = {
        ok: "text-bg-success",
        fail: "text-bg-danger",
        warn: "text-bg-warning",
        none: "bg-body-secondary text-body-secondary",
    };
    const pillIcon: Record<Pill, string> = {
        ok: "bi-check-lg",
        fail: "bi-x-lg",
        warn: "bi-exclamation-lg",
        none: "bi-dash",
    };
</script>

<ReportSection
    id="mail-servers-details"
    title="Mail Servers"
    icon="hdd-network"
    grade={result?.grade}
    score={result?.score}
    unavailable={!loading && !!result && result.score === undefined}
    {status}
    open
    class={className}
>
    <div class="card-body">
        <p class="text-body-secondary small mb-3">
            What a sending server sees when it delivers mail to this domain. These servers receive
            your bounces, replies and DMARC and TLS-RPT reports. No mail is sent: every transaction
            stops before DATA.
        </p>

        {#if loading}
            <div class="text-center py-4">
                <TileLoader class="mb-3" label="Probing the mail servers…" />
                <p class="text-muted mb-0">
                    Connecting to each mail server on port 25. Slow servers can take up to a minute.
                </p>
            </div>
        {:else if error}
            <p class="text-danger mb-0">{error}</p>
        {:else if result}
            {#each issues as issue, i (i)}
                <IssueNote {issue} />
            {/each}

            {#if result.status === "null_mx"}
                <p class="mb-0">
                    The domain publishes a null MX (<code>MX 0 .</code>): it declares that it
                    accepts no mail, so there is no server to probe.
                </p>
            {/if}

            {#if result.servers && result.servers.length > 0 && result.status !== "inconclusive"}
                <div class="table-responsive mt-3">
                    <table class="table table-sm align-middle mail-servers mb-2">
                        <thead>
                            <tr>
                                <th scope="col">Server</th>
                                {#each steps as step (step.label)}
                                    <th scope="col" class="text-center small" title={step.title}
                                        >{step.label}</th
                                    >
                                {/each}
                            </tr>
                        </thead>
                        <tbody>
                            {#each result.servers as srv (srv.host)}
                                {#if srv.endpoints.length === 0}
                                    <tr>
                                        <td>
                                            <span class="font-monospace">{srv.host}</span>
                                            <span class="badge text-bg-light border ms-1"
                                                >{srv.priority}</span
                                            >
                                        </td>
                                        <td colspan={steps.length} class="small text-danger">
                                            {srv.skip_reason ?? "Not probed"}
                                        </td>
                                    </tr>
                                {/if}
                                {#each srv.endpoints as ep (ep.ip)}
                                    <tr>
                                        <td>
                                            <div>
                                                <span class="font-monospace">{srv.host}</span>
                                                <span class="badge text-bg-light border ms-1"
                                                    >{srv.priority}</span
                                                >
                                            </div>
                                            <div class="small text-body-secondary font-monospace">
                                                {ep.ip}
                                                <span class="badge text-bg-light border"
                                                    >{ep.ipv6 ? "IPv6" : "IPv4"}</span
                                                >
                                            </div>
                                        </td>
                                        {#if ep.skip_reason}
                                            <td colspan={steps.length} class="small text-warning">
                                                {ep.skip_reason}
                                            </td>
                                        {:else}
                                            {#each steps as step (step.label)}
                                                {@const state = step.state(ep)}
                                                <td class="text-center">
                                                    <span
                                                        class="badge rounded-pill {pillClass[
                                                            state
                                                        ]}"
                                                        title="{step.title}{step.detail?.(ep)
                                                            ? `: ${step.detail(ep)}`
                                                            : ''}"
                                                    >
                                                        <i class="bi {pillIcon[state]}"></i>
                                                        <span class="visually-hidden"
                                                            >{step.title}: {state}</span
                                                        >
                                                    </span>
                                                </td>
                                            {/each}
                                        {/if}
                                    </tr>
                                    {#if ep.error && ep.probed}
                                        <tr class="endpoint-error">
                                            <td></td>
                                            <td
                                                colspan={steps.length}
                                                class="small text-muted pt-0"
                                            >
                                                Stopped at {ep.error}
                                            </td>
                                        </tr>
                                    {/if}
                                {/each}
                            {/each}
                        </tbody>
                    </table>
                </div>
                <p class="small text-body-secondary mb-2">
                    {#if result.mta_sts_enforced}
                        <i class="bi bi-shield-check text-success me-1"></i>MTA-STS is enforced on
                        every server.
                    {:else if result.dane_valid}
                        <i class="bi bi-shield-check text-success me-1"></i>DANE protects every
                        server.
                    {:else}
                        <i class="bi bi-shield me-1"></i>Deploy MTA-STS in enforce mode or DANE to
                        reach A+.
                    {/if}
                    {#if result.open_relay_tested === false}
                        The open relay test is not run on this instance.
                    {/if}
                    {#if result.cached_at}
                        Probed {new Date(result.cached_at).toLocaleString()}.
                    {/if}
                </p>
            {/if}
            <DocLinks
                docs={[docs.mxLookup, docs.starttls, docs.mtaSts, docs.dane, docs.postmaster]}
            />
        {/if}
    </div>
</ReportSection>

<style>
    .mail-servers th {
        white-space: nowrap;
    }

    .endpoint-error td {
        border-top: 0;
    }
</style>
