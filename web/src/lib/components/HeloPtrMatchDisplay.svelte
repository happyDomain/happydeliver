<script lang="ts">
    import type { Issue } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        heloHostname?: string;
        ptrRecords?: string[];
        heloPtrMatch?: boolean;
        issues?: Issue[];
    }

    let { heloHostname, ptrRecords, heloPtrMatch, issues }: Props = $props();

    const normalize = (host: string) => host.replace(/\.$/, "").trim().toLowerCase();

    // Local comparison, identical to the per-record marks below, so the summary can never
    // contradict them.
    const localMatch = $derived(
        !!heloHostname &&
            !!ptrRecords &&
            ptrRecords.some((ptr) => normalize(heloHostname) === normalize(ptr)),
    );

    // Prefer the backend verdict when it is present; otherwise fall back to the
    // local comparison (e.g. for results produced before helo_ptr_match existed).
    const isMatch = $derived(heloPtrMatch ?? localMatch);
    const hasPtr = $derived(!!ptrRecords && ptrRecords.length > 0);
</script>

{#if heloHostname}
    <!-- Without a PTR record there is nothing to compare: the reverse DNS check says why. -->
    <CheckCard
        id="dns-helo-ptr"
        title="HELO / PTR Consistency"
        tag="HELO"
        status={!hasPtr ? "neutral" : isMatch ? "pass" : "warn"}
        summary={!hasPtr
            ? `${heloHostname}, no PTR to compare with`
            : isMatch
              ? heloHostname
              : `${heloHostname} differs from the reverse DNS`}
        docs={[docs.ehlo]}
        {issues}
    >
        <div class="card-body">
            <dl class="check-facts">
                <dt>Announced HELO</dt>
                <dd><code>{heloHostname}</code></dd>
                {#if hasPtr}
                    <dt>PTR</dt>
                    <dd>
                        {#each ptrRecords! as ptr, i (i)}
                            <div>
                                <code>{ptr}</code>
                                {#if normalize(heloHostname) === normalize(ptr)}
                                    <span class="small text-success ms-1">same</span>
                                {:else}
                                    <span class="small text-body-secondary ms-1">different</span>
                                {/if}
                            </div>
                        {/each}
                    </dd>
                {/if}
            </dl>
            <p class="check-about">
                The HELO (or EHLO) hostname is the name the sending server announces when it
                connects. Many receivers check that it matches the reverse DNS of the sending IP; a
                mismatch is a common spam signal.
            </p>
        </div>
    </CheckCard>
{/if}
