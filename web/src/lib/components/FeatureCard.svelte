<script lang="ts">
    interface Props {
        icon: string;
        title: string;
        description: string;
        variant?: "primary" | "success" | "warning" | "danger" | "info" | "secondary";
        /* Set on the features that have a tool of their own behind them, to
           send the reader straight to it. Both are needed for the call to
           action to appear: a link with no wording is not one. */
        href?: string;
        linkLabel?: string;
    }

    let { icon, title, description, variant = "primary", href, linkLabel }: Props = $props();
</script>

<div class="card h-100 text-center p-4">
    <div class="feature-icon bg-{variant} bg-opacity-10 text-{variant} mx-auto">
        <i class="bi {icon}"></i>
    </div>
    <h5 class="fw-bold">{title}</h5>
    <p class="text-muted small">
        {description}
    </p>
    {#if href && linkLabel}
        <div class="mt-auto pt-2">
            <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- the caller passes an already resolved route -->
            <a {href} class="btn btn-sm btn-outline-{variant}">
                {linkLabel}
                <i class="bi bi-arrow-right ms-1"></i>
            </a>
        </div>
    {/if}
</div>

<style>
    .feature-icon {
        width: 4rem;
        height: 4rem;
        border-radius: 0.75rem;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.5rem;
        margin-bottom: 1rem;
    }
</style>
