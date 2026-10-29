<script lang="ts" module>
    /** Context key telling a CheckCard it is a row of a list rather than a card of its own. */
    export const checkListKey = Symbol("check-list");
</script>

<script lang="ts">
    import { setContext, type Snippet } from "svelte";

    interface Props {
        /** What the checks below are about: a server, a domain. */
        title?: string;
        /** The subject itself (a hostname, a domain), shown next to the title. */
        subject?: string;
        /** Said next to the subject: how it relates to the rest of the report. */
        aside?: Snippet;
        children: Snippet;
    }

    let { title, subject, aside, children }: Props = $props();

    setContext(checkListKey, true);
</script>

<!-- Checks about one subject, as rows under one heading: the section around them is the
     only card, so nothing is nested more than once. -->
<section class="check-list">
    {#if title}
        <h5
            class="check-list-title d-flex flex-wrap align-items-baseline column-gap-2 mb-1 small text-uppercase text-body-secondary"
        >
            {title}
            {#if subject}
                <span class="check-list-subject font-monospace text-lowercase text-body"
                    >{subject}</span
                >
            {/if}
            {@render aside?.()}
        </h5>
    {/if}
    {@render children()}
</section>

<style>
    /* The value a list is about (a domain, an address): a light frame sets it apart from the
       title it follows. */
    .check-list-subject {
        padding: 0.05em 0.4em;
        border: 1px solid var(--hd-border-1);
        border-radius: var(--hd-radius-sm);
        font-size: 0.95rem;
    }
</style>
