<script lang="ts">
    import type { DocLink } from "#lib/docs.js";

    interface Props {
        docs?: DocLink[];
        /** What introduces the links; the references alone read as a list of codes. */
        label?: string;
        class?: string;
    }

    let { docs = [], label = "Learn more:", class: className = "" }: Props = $props();
</script>

{#if docs.length > 0}
    <!-- eslint-disable svelte/no-navigation-without-resolve -- external references -->
    <div class="doc-links small {className}">
        <i class="bi bi-book me-1" aria-hidden="true"></i>
        {#if label}<span class="text-muted">{`${label} `}</span>{/if}
        {#each docs as doc, i (doc.url + i)}
            {#if i > 0}<span class="text-muted" aria-hidden="true">,&#32;</span>{/if}<a
                href={doc.url}
                target="_blank"
                rel="noopener noreferrer"
                title={doc.title}
                >{doc.label}{#if doc.title}<span class="text-body-secondary d-none d-sm-inline"
                        >{`: ${doc.title}`}</span
                    >{/if}</a
            >
        {/each}
    </div>
    <!-- eslint-enable svelte/no-navigation-without-resolve -->
{/if}
