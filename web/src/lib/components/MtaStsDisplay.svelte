<script lang="ts">
    import type { Issue, MtastsResult } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        mtaSts?: MtastsResult;
        issues?: Issue[];
    }

    let { mtaSts, issues }: Props = $props();

    const summary = $derived(
        mtaSts?.status === "absent"
            ? "No MTA-STS policy"
            : mtaSts?.mode
              ? `Policy in ${mtaSts.mode} mode`
              : (mtaSts?.record_error ?? mtaSts?.policy_error ?? "Policy published"),
    );
</script>

{#if mtaSts}
    <CheckCard
        id="dns-mta-sts"
        title="Strict Transport Security for mail"
        tag="MTA-STS"
        status={mtaSts.status === "valid"
            ? "pass"
            : mtaSts.status === "absent"
              ? "neutral"
              : "fail"}
        {summary}
        docs={[docs.mtaSts]}
        {issues}
    >
        <div class="card-body">
            {#if mtaSts.status !== "absent"}
                <dl class="check-facts">
                    {#if mtaSts.record}
                        <dt>Record</dt>
                        <dd><code>{mtaSts.record}</code></dd>
                    {/if}
                    {#if mtaSts.policy_url}
                        <dt>Policy</dt>
                        <dd>
                            <!-- eslint-disable svelte/no-navigation-without-resolve -- the domain's own policy -->
                            <a
                                class="font-monospace small"
                                href={mtaSts.policy_url}
                                target="_blank"
                                rel="noopener noreferrer">{mtaSts.policy_url}</a
                            >
                            <!-- eslint-enable svelte/no-navigation-without-resolve -->
                            {#if mtaSts.policy_error}
                                <div class="small text-danger">{mtaSts.policy_error}</div>
                            {/if}
                        </dd>
                    {/if}
                    {#if mtaSts.mode}
                        <dt>Mode</dt>
                        <dd><code>{mtaSts.mode}</code></dd>
                    {/if}
                    {#if mtaSts.max_age !== undefined}
                        <dt>Max age</dt>
                        <dd>
                            {mtaSts.max_age} s
                            <span class="text-body-secondary"
                                >({Math.round(mtaSts.max_age / 86400)} days)</span
                            >
                        </dd>
                    {/if}
                    {#if mtaSts.mx_coverage && mtaSts.mx_coverage.length > 0}
                        <dt>MX covered</dt>
                        <dd>
                            <ul class="list-unstyled mb-0">
                                {#each mtaSts.mx_coverage as cov (cov.host)}
                                    <li>
                                        <i
                                            class="bi me-1 {cov.covered
                                                ? 'bi-check-circle text-success'
                                                : 'bi-x-circle text-danger'}"
                                        ></i>
                                        <span class="font-monospace">{cov.host}</span>
                                        {#if cov.pattern && cov.pattern !== cov.host}
                                            <span class="small text-body-secondary"
                                                >by <code>{cov.pattern}</code></span
                                            >
                                        {/if}
                                    </li>
                                {/each}
                            </ul>
                        </dd>
                    {:else if mtaSts.mx && mtaSts.mx.length > 0}
                        <dt>mx</dt>
                        <dd class="font-monospace">{mtaSts.mx.join(", ")}</dd>
                    {/if}
                    {#if mtaSts.record_error}
                        <dt>Error</dt>
                        <dd class="text-danger">{mtaSts.record_error}</dd>
                    {/if}
                </dl>
            {/if}
            <p class="check-about">
                MTA-STS tells sending servers to deliver to your MX only over TLS with a valid
                certificate, so that nobody on the way can strip encryption or impersonate your
                servers.
            </p>
        </div>
    </CheckCard>
{/if}
