<script lang="ts">
    import type { DnssecResult, Issue } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        dnssec?: DnssecResult;
        /** MX hosts publishing TLSA records. */
        daneHosts?: string[];
        issues?: Issue[];
    }

    let { dnssec, daneHosts = [], issues }: Props = $props();

    const meaning: Record<DnssecResult["status"], string> = {
        secure: "Signed and validated",
        insecure: "Zone not signed",
        unvalidated: "Signed, but not validated by this instance's resolver",
        broken: "Validation fails: validating resolvers cannot resolve the domain",
        unknown: "Could not be determined",
    };
</script>

{#if dnssec}
    <CheckCard
        id="dns-dnssec"
        title="DNS Security Extensions"
        tag="DNSSEC"
        status={dnssec.status === "secure"
            ? "pass"
            : dnssec.status === "broken"
              ? "fail"
              : dnssec.status === "insecure"
                ? "neutral"
                : "info"}
        summary={meaning[dnssec.status]}
        docs={[docs.dnssec, docs.dane]}
        {issues}
    >
        <div class="card-body">
            <dl class="check-facts">
                <dt>Status</dt>
                <dd>{meaning[dnssec.status]}</dd>
                {#if daneHosts.length > 0}
                    <dt>DANE</dt>
                    <dd>
                        TLSA records published for
                        <span class="font-monospace">{daneHosts.join(", ")}</span>
                    </dd>
                {/if}
                {#if dnssec.error}
                    <dt>Details</dt>
                    <dd class="small">{dnssec.error}</dd>
                {/if}
            </dl>
            <p class="check-about">
                DNSSEC signs the records of your zone, so that resolvers can tell forged answers
                from yours. It is what DANE builds on to pin the certificates of your mail servers.
            </p>
        </div>
    </CheckCard>
{/if}
