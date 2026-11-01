<script lang="ts">
    import type { Issue, TlsrptResult } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        tlsRpt?: TlsrptResult;
        issues?: Issue[];
    }

    let { tlsRpt, issues }: Props = $props();
</script>

{#if tlsRpt}
    <CheckCard
        id="dns-tls-rpt"
        title="SMTP TLS Reporting"
        tag="TLS-RPT"
        status={tlsRpt.status === "valid"
            ? "pass"
            : tlsRpt.status === "absent"
              ? "neutral"
              : "fail"}
        summary={tlsRpt.record ?? tlsRpt.error ?? "No TLS-RPT record"}
        summaryFoldedOnly={!!tlsRpt.record}
        docs={[docs.tlsRpt]}
        {issues}
    >
        <div class="card-body">
            {#if tlsRpt.record || tlsRpt.error}
                <dl class="check-facts">
                    {#if tlsRpt.record}
                        <dt>Record</dt>
                        <dd><code>{tlsRpt.record}</code></dd>
                    {/if}
                    {#if tlsRpt.rua && tlsRpt.rua.length > 0}
                        <dt>Reports to</dt>
                        <dd class="font-monospace">{tlsRpt.rua.join(", ")}</dd>
                    {/if}
                    {#if tlsRpt.error}
                        <dt>Error</dt>
                        <dd class="text-danger">{tlsRpt.error}</dd>
                    {/if}
                </dl>
            {/if}
            <p class="check-about">
                TLS-RPT asks sending servers to report daily the failures they met delivering to you
                over TLS: the warning you get before an expired certificate or a wrong MTA-STS
                policy costs you mail.
            </p>
        </div>
    </CheckCard>
{/if}
