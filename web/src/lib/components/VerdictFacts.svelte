<script lang="ts">
    import type { Snippet } from "svelte";

    interface Props {
        /** The verdict as the receiver wrote it, quoted under what was read out of it. */
        raw?: string;
        /** FactRows: the verdict, and the facts the receiver reported with it. */
        children: Snippet;
    }

    let { raw, children }: Props = $props();
</script>

<div class="verdict-facts">
    <section class="verdict-facts-reported">
        <h6 class="verdict-facts-title">Reported by the receiver</h6>
        <dl class="fact-list">
            {@render children()}
        </dl>
        {#if raw}
            <!-- The evidence, as is: needed to debug a failure, so always there, but quiet. -->
            <p class="check-raw">
                <span class="check-raw-label">Raw</span>
                <code>{raw}</code>
            </p>
        {/if}
    </section>
</div>
