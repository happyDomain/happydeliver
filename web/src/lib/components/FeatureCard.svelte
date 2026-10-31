<script lang="ts">
    interface Props {
        icon: string;
        title: string;
        description: string;
        /* "sky" is a decorative tone, outside Bootstrap's theme colours: info
           and primary are both purple in the HappyDomain theme, so the blue
           has to come from the palette directly. */
        variant?: "primary" | "success" | "warning" | "danger" | "info" | "secondary" | "sky";
        /* Set on the features that have a tool of their own behind them, to
           send the reader straight to it. Both are needed for the call to
           action to appear: a link with no wording is not one. */
        href?: string;
        linkLabel?: string;
    }

    let { icon, title, description, variant = "primary", href, linkLabel }: Props = $props();

    const iconTone = $derived(
        variant === "sky" ? "tone-sky" : `bg-${variant} bg-opacity-10 text-${variant}`,
    );
    // No btn-outline-sky in Bootstrap: such a call to action takes the brand colour.
    const buttonVariant = $derived(variant === "sky" ? "primary" : variant);
</script>

<div class="card h-100 text-center p-4">
    <div
        class="feature-icon d-flex align-items-center justify-content-center fs-4 mb-3 {iconTone} mx-auto"
    >
        <i class="bi {icon}"></i>
    </div>
    <h5 class="fw-bold">{title}</h5>
    <p class="text-muted small">
        {description}
    </p>
    {#if href && linkLabel}
        <div class="mt-auto pt-2">
            <!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- the caller passes an already resolved route -->
            <a {href} class="btn btn-sm btn-outline-{buttonVariant}">
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
    }

    /* Same recipe as bg-* bg-opacity-10 text-*, the solid shade with a tint
       of it behind; a bit more tint, as a cool blue greys out on the cream
       canvas at 10%. */
    .tone-sky {
        --tone: var(--hd-sky-600);
        color: var(--tone);
        background-color: color-mix(in srgb, var(--tone) 14%, transparent);
    }

    :global([data-bs-theme="dark"]) .tone-sky {
        --tone: var(--hd-sky-400);
    }
</style>
