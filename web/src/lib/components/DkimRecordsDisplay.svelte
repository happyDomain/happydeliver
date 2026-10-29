<script lang="ts">
    import type { DkimRecord, Issue } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        dkimRecords?: DkimRecord[];
        issues?: Issue[];
    }

    let { dkimRecords, issues }: Props = $props();

    const records = $derived(dkimRecords ?? []);

    const dkimSummary = $derived(
        records.length > 0
            ? records
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
    status={records.length === 0 ? "neutral" : records.some((r) => !r.valid) ? "fail" : "pass"}
    summary={dkimSummary}
    docs={[docs.dkim, docs.dkimKeySize]}
    {issues}
>
    <div class="card-body">
        {#if records.length > 0}
            <dl class="check-facts">
                {#each records as dkim, i (dkim.selector + "-" + dkim.domain + "-" + i)}
                    <dt>
                        <span class="font-monospace">{dkim.selector}._domainkey.{dkim.domain}</span>
                    </dt>
                    <dd>
                        {#if dkim.key_size}
                            {dkim.key_size}-bit {(dkim.key_type ?? "rsa").toUpperCase()}
                            {#if dkim.signing_algorithm}
                                <span class="text-body-secondary"
                                    >, signed with {dkim.signing_algorithm}</span
                                >
                            {/if}
                        {/if}
                        {#if dkim.record}
                            <code class="d-block small text-truncate">{dkim.record}</code>
                        {/if}
                        {#if dkim.error}
                            <div class="small text-danger">{dkim.error}</div>
                        {/if}
                    </dd>
                {/each}
            </dl>
        {/if}
        <p class="check-about">
            DKIM signs messages so receivers can check they were sent by the domain and not altered
            on the way, against the public key the domain publishes in DNS.
        </p>
    </div>
</CheckCard>
