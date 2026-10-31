<script lang="ts">
    import type { Snippet } from "svelte";

    interface Props {
        /** What the first block holds, when not the facts the receiver reported. */
        title?: string;
        /** The verdict as the receiver wrote it, quoted under what was read out of it. */
        raw?: string;
        /** FactRows: the verdict, and the facts the receiver reported with it. */
        children: Snippet;
        /**
         * FactRows: what the report knows besides, to understand the verdict or to act on
         * it (the records this instance fetched, the other verdicts it rests on).
         */
        help?: Snippet;
        /** The checks of the report where to go on, after the help, as anchors in the page. */
        links?: { href: string; label: string }[];
    }

    let { title = "Reported by the receiver", raw, children, help, links }: Props = $props();

    const hasHelp = $derived(!!help || !!links?.length);
</script>

<!-- What led to the verdict, apart from what helps act on it: side by side on a wide
     screen, the one under the other on a narrow one. -->
<div class={["verdict-facts", hasHelp && "with-help"]}>
    <section class="verdict-facts-reported">
        <h6 class="verdict-facts-title">{title}</h6>
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
    {#if hasHelp}
        <section class="verdict-facts-help">
            <h6 class="verdict-facts-title">To go further</h6>
            {#if help}
                <dl class="fact-list">
                    {@render help()}
                </dl>
            {/if}
            {#if links?.length}
                <p class="verdict-facts-links">
                    <i class="bi bi-arrow-right-short" aria-hidden="true"></i>
                    {#each links as link, i (link.href)}
                        {#if i > 0}
                            <span class="mx-1" aria-hidden="true">·</span>
                        {/if}
                        <!-- eslint-disable svelte/no-navigation-without-resolve -- anchors in this page -->
                        <a href={link.href}>{link.label}</a>
                        <!-- eslint-enable svelte/no-navigation-without-resolve -->
                    {/each}
                </p>
            {/if}
        </section>
    {/if}
</div>
