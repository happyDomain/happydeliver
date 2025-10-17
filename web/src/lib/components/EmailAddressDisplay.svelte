<script lang="ts">
    interface Props {
        email: string;
    }

    let { email }: Props = $props();
    let copied = $state(false);

    async function copyToClipboard() {
        try {
            await navigator.clipboard.writeText(email);
            copied = true;
            setTimeout(() => (copied = false), 2000);
        } catch (err) {
            console.error("Failed to copy:", err);
        }
    }
</script>

<div class="bg-light rounded p-4">
    <div class="d-flex align-items-center justify-content-center gap-3">
        <code class="fs-5 text-primary fw-bold">{email}</code>
        <button
            class="btn btn-sm btn-outline-primary clipboard-btn"
            onclick={copyToClipboard}
            title="Copy to clipboard"
        >
            <i class={copied ? "bi bi-check2" : "bi bi-clipboard"}></i>
        </button>
    </div>
    {#if copied}
        <small class="text-success d-block mt-2">
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
