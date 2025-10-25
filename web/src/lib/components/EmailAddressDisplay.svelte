<script lang="ts">
    import { theme } from "$lib/stores/theme";

    interface Props {
        email: string;
    }

    let { email }: Props = $props();
    let copied = $state(false);
    let inputElement: HTMLInputElement;

    async function copyToClipboard() {
        try {
            await navigator.clipboard.writeText(email);
            copied = true;
            setTimeout(() => (copied = false), 2000);
        } catch (err) {
            console.error("Failed to copy:", err);
        }
    }

    function handleFocus(event: FocusEvent) {
        const target = event.target as HTMLInputElement;
        target.select();
        copyToClipboard();
    }
</script>

<div
    class="rounded rounded-4 p-4"
    class:bg-light={$theme === "light"}
    class:bg-secondary={$theme !== "light"}
>
    <div class="input-group">
        <input
            bind:this={inputElement}
            type="text"
            class="form-control text-center fs-5 text-primary fw-bold font-monospace"
            value={email}
            readonly
            onfocus={handleFocus}
        />
        <button
            class="btn btn-outline-primary clipboard-btn"
            class:btn-outline-primary={$theme === "light"}
            class:btn-primary={$theme !== "light"}
            onclick={copyToClipboard}
            title="Copy to clipboard"
        >
            <i class={copied ? "bi bi-check2" : "bi bi-clipboard"}></i>
        </button>
    </div>
    {#if copied}
        <small class="text-success d-block mt-2 text-center">
            <i class="bi bi-check2"></i> Copied to clipboard!
        </small>
    {/if}
</div>

<style>
    .clipboard-btn {
        transition: all 0.2s ease;
    }

    .clipboard-btn:hover {
        transform: scale(1.1);
    }
</style>
