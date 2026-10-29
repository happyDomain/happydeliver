<script lang="ts">
    import type { Issue, SpfRecord } from "#lib/api/types.gen.js";
    import { docs } from "#lib/docs.js";
    import CheckCard from "./CheckCard.svelte";

    interface Props {
        heloSpfRecord?: SpfRecord;
        issues?: Issue[];
    }

    let { heloSpfRecord, issues }: Props = $props();

    // A published policy is a bonus, never a requirement: its absence is a suggestion,
    // so nothing here is ever styled as an error.
    const hasPolicy = $derived(!!heloSpfRecord?.valid);
</script>

{#if heloSpfRecord}
    <CheckCard
        id="dns-helo-spf"
        title="SPF for the HELO Hostname"
        tag="SPF"
        status={hasPolicy ? "pass" : "info"}
        summary={heloSpfRecord.record ?? "No policy published (optional)"}
        summaryFoldedOnly={!!heloSpfRecord.record}
        docs={[docs.spfHelo]}
        {issues}
    >
        <div class="card-body">
            <dl class="check-facts">
                {#if heloSpfRecord.domain}
                    <dt>Announced HELO</dt>
                    <dd><code>{heloSpfRecord.domain}</code></dd>
                {/if}
                <dt>Policy</dt>
                <dd>
                    {#if heloSpfRecord.record}
                        <code>{heloSpfRecord.record}</code>
                    {:else}
                        <!-- What the lookup actually returned: "none" would hide a hostname
                             that does not resolve at all -->
                        {heloSpfRecord.error ?? "none"}
                    {/if}
                </dd>
            </dl>
            <p class="check-about">
                SPF can authenticate, besides the envelope sender, the hostname the server announces
                at HELO (<a
                    href="https://www.rfc-editor.org/rfc/rfc7208.html#section-2.3"
                    target="_blank"
                    rel="noreferrer">RFC 7208, section 2.3</a
                >). A bounce has an empty envelope sender, so it is the only identity SPF can check
                there (<a
                    href="https://www.rfc-editor.org/rfc/rfc7208.html#section-2.4"
                    target="_blank"
                    rel="noreferrer">section 2.4</a
                >). Optional: this check never affects the score.
            </p>
        </div>
    </CheckCard>
{/if}
