<script lang="ts">
    import type { ClassValue } from "svelte/elements";

    import type { Issue, MxRecord, ReturnOkDomain } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        id?: string;
        class?: ClassValue;
        mxRecords?: MxRecord[];
        /** Whether the domain can receive mail at all, MX or not. */
        returnOk?: ReturnOkDomain;
        title?: string;
        /** What mail these servers receive: replies, bounces. */
        description?: string;
        issues?: Issue[];
    }

    let {
        id,
        class: className,
        mxRecords = [],
        returnOk,
        title = "Mail Exchangers",
        description,
        issues,
    }: Props = $props();

    const allValid = $derived(mxRecords.every((r) => r.valid));
    const sorted = $derived([...mxRecords].sort((a, b) => a.priority - b.priority));

    const nullMx = $derived(mxRecords.length === 1 && mxRecords[0].null_mx === true);

    const summary = $derived(
        nullMx
            ? "Null MX: this domain declares it accepts no mail"
            : mxRecords.length > 0
              ? sorted.map((mx) => mx.host).join(", ")
              : returnOk?.status === "warn"
                ? "No MX record, mail goes to the A/AAAA address"
                : returnOk?.status === "fail"
                  ? "No MX nor A/AAAA record: cannot receive mail"
                  : "No MX record",
    );
</script>

{#if mxRecords.length > 0 || returnOk}
    <CheckCard
        {id}
        class={className}
        {title}
        tag="MX"
        status={returnOk?.status === "fail" || !allValid
            ? "fail"
            : returnOk?.status === "warn"
              ? "warn"
              : "pass"}
        {summary}
        docs={[docs.mxLookup]}
        {issues}
    >
        <div class="card-body">
            {#if nullMx}
                <p class="small mb-2">
                    <span class="font-monospace">MX 0 .</span> is an RFC 7505 null MX: the domain states
                    that it receives no mail, so replies and bounces sent to it are refused.
                </p>
            {:else if sorted.length > 0}
                <dl class="check-facts">
                    {#each sorted as mx, i (i)}
                        <dt>{mx.priority}</dt>
                        <dd>
                            <span class="font-monospace">{mx.host}</span>
                            {#if mx.cname_target}
                                <span class="small text-warning ms-1"
                                    >alias of <span class="font-monospace">{mx.cname_target}</span
                                    ></span
                                >
                            {/if}
                            {#if !mx.valid}
                                <span class="small text-danger ms-1">{mx.error ?? "invalid"}</span>
                            {:else if mx.error}
                                <span class="small text-warning ms-1">{mx.error}</span>
                            {/if}
                            {#if mx.addresses && mx.addresses.length > 0}
                                <div class="small text-muted font-monospace">
                                    {mx.addresses.join(", ")}
                                </div>
                            {/if}
                        </dd>
                    {/each}
                </dl>
            {/if}
            {#if returnOk?.org_domain}
                <p class="small mb-2">
                    Found through the organizational domain <span class="font-monospace"
                        >{returnOk.org_domain}</span
                    >.
                </p>
            {/if}
            <p class="check-about">
                {#if description}{description}{/if}
                A domain should publish MX records; an A/AAAA record works as an implicit fallback, and
                a domain with neither cannot receive any mail.
            </p>
        </div>
    </CheckCard>
{/if}
