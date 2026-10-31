<script lang="ts">
    import type { Snippet } from "svelte";

    interface Props {
        /** What the row is about: a name, an address, the verdict. */
        label: string;
        /** The value, unless the content of the row gives it. */
        value?: string;
        /** Shows the value in monospace: a hostname, an address, a record. */
        mono?: boolean;
        /** Whether the value is the one it should be, marked next to it when it can be told. */
        ok?: boolean;
        /** Words the mark, when "matches" or "differs" would not say it. */
        okLabel?: string;
        /** The value, when it takes more than a string. */
        children?: Snippet;
    }

    let { label, value, mono = false, ok, okLabel, children }: Props = $props();
</script>

<dt>{label}</dt>
<dd>
    {#if children}
        {@render children()}
    {:else if value !== undefined}
        <span class={{ "font-monospace": mono }}>{value}</span>
    {:else}
        <span class="text-body-secondary">unknown</span>
    {/if}
    {#if ok !== undefined}
        <span class={["fact-mark small text-nowrap", ok ? "text-success" : "text-danger"]}>
            <i class={["bi", ok ? "bi-check-lg" : "bi-x-lg"]} aria-hidden="true"></i>
            {okLabel ?? (ok ? "matches" : "differs")}
        </span>
    {/if}
</dd>
