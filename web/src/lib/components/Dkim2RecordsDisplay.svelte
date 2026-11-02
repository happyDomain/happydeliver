<script lang="ts">
    import type { Dkim2PolicyRecord, Dkim2Record, Issue } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        dkim2Records?: Dkim2Record[];
        policyRecords?: Dkim2PolicyRecord[];
        issues?: Issue[];
    }

    let { dkim2Records, policyRecords, issues }: Props = $props();

    const records = $derived(dkim2Records ?? []);

    // The keys of each signature of the chain, in the order of the chain.
    const signatures = $derived.by(() => {
        const chain: { instance: number; domain: string; keys: Dkim2Record[] }[] = [];
        for (const record of records) {
            let signature = chain.find(
                (s) => s.instance === record.instance && s.domain === record.domain,
            );
            if (!signature) {
                signature = { instance: record.instance, domain: record.domain, keys: [] };
                chain.push(signature);
            }
            signature.keys.push(record);
        }
        return chain;
    });

    /** Whether the signature offers alternatives, any one of which is enough. */
    function hasAlternatives(keys: Dkim2Record[]): boolean {
        return new Set(keys.map((k) => k.alternative ?? 0)).size > 1;
    }

    /** Whether some alternative of the signature has every key it needs. */
    function usable(keys: Dkim2Record[]): boolean {
        const alternatives = new Set(keys.map((k) => k.alternative ?? 0));
        return [...alternatives].some((alt) =>
            keys.filter((k) => (k.alternative ?? 0) === alt).every((k) => k.valid),
        );
    }

    const summary = $derived(
        signatures.length === 0
            ? "No DKIM2 signature found"
            : signatures
                  .map(
                      (s) =>
                          `i=${s.instance} ${s.domain}${usable(s.keys) ? "" : " (no usable key)"}`,
                  )
                  .join(", "),
    );

    const policies = $derived((policyRecords ?? []).filter((p) => p.record || p.error));
</script>

<CheckCard
    id="dns-dkim2"
    title="DomainKeys Identified Mail v2 (draft)"
    tag="DKIM2"
    status={signatures.length === 0
        ? "neutral"
        : signatures.some((s) => !usable(s.keys))
          ? "fail"
          : records.some((r) => !r.valid)
            ? "improve"
            : "pass"}
    {summary}
    docs={[docs.dkim2Dns, docs.dkim2]}
    {issues}
>
    <div class="card-body">
        {#each signatures as signature (signature.instance + "-" + signature.domain)}
            <h6 class="small fw-semibold mb-1">
                Signature i={signature.instance}
                <span class="font-monospace fw-normal">{signature.domain}</span>
                {#if signature.instance === 1}
                    <span class="text-body-secondary fw-normal">(originator)</span>
                {/if}
            </h6>
            {#if hasAlternatives(signature.keys)}
                <p class="small text-body-secondary mb-1">
                    Signed with alternatives: one verifying is enough.
                </p>
            {/if}
            <dl class="check-facts">
                {#each signature.keys as key, i (key.selector + "-" + i)}
                    <dt>
                        <span class="font-monospace">{key.selector}._domainkey.{key.domain}</span>
                    </dt>
                    <dd>
                        {#if key.valid}
                            {#if key.key_size}
                                {key.key_size}-bit
                            {/if}
                            {(key.key_type ?? "rsa").toUpperCase()}
                        {/if}
                        {#if key.signing_algorithm}
                            <span class="text-body-secondary"
                                >{key.valid ? ", " : ""}signed with {key.signing_algorithm}</span
                            >
                        {/if}
                        {#if key.record}
                            <code class="d-block small text-truncate">{key.record}</code>
                        {/if}
                        {#if key.deprecated_tags?.length}
                            <div class="small text-body-secondary">
                                Ignored by DKIM2:
                                {#each key.deprecated_tags as tag, j (tag)}<code>{tag}=</code>{j <
                                    key.deprecated_tags.length - 1
                                        ? ", "
                                        : ""}{/each}
                            </div>
                        {/if}
                        {#if key.error}
                            <div class="small text-danger">{key.error}</div>
                        {/if}
                    </dd>
                {/each}
            </dl>
        {/each}

        {#if policies.length > 0}
            <h6 class="small fw-semibold mb-1">Domain Policy</h6>
            <dl class="check-facts">
                {#each policies as policy (policy.domain)}
                    <dt><span class="font-monospace">_domainkey.{policy.domain}</span></dt>
                    <dd>
                        {#if policy.record}
                            {policy.strict
                                ? "Strict: subdomains may not sign From addresses of this domain."
                                : "Subdomains may sign From addresses of this domain."}
                            <code class="d-block small text-truncate">{policy.record}</code>
                        {/if}
                        {#if policy.error}
                            <div class="small text-danger">{policy.error}</div>
                        {/if}
                    </dd>
                {/each}
            </dl>
        {/if}

        <p class="check-about">
            DKIM2, still an IETF draft, signs each hop of the message, so receivers can check the
            path it travelled and the changes made along the way. Its keys are published like DKIM
            keys, and the same key can serve both.
        </p>
    </div>
</CheckCard>
