<script lang="ts">
    import "bootstrap-icons/font/bootstrap-icons.css";
    import "@fontsource-variable/lexend";
    import "@fontsource-variable/roboto";
    import "@fontsource-variable/jetbrains-mono";
    import "@fontsource-variable/jetbrains-mono/wght-italic.css";
    import "../app.scss";

    import favicon from "#lib/assets/favicon.svg";
    import { resolve } from "$app/paths";

    import Logo from "#lib/components/Logo.svelte";
    import { appConfig } from "#lib/stores/config.js";
    import { theme } from "#lib/stores/theme.js";
    import { onMount } from "svelte";

    interface Props {
        children?: import("svelte").Snippet;
    }

    let { children }: Props = $props();

    onMount(() => {
        document.documentElement.setAttribute("data-bs-theme", $theme);
    });

    function toggleTheme() {
        $theme = $theme === "light" ? "dark" : "light";
    }
</script>

<svelte:head>
    <link rel="icon" href={favicon} />
</svelte:head>

<div class="min-vh-100 d-flex flex-column">
    <nav class="navbar navbar-expand-lg py-2" id="nav">
        <div class="container">
            <a class="navbar-brand p-0 me-3" href={resolve("/")}>
                {#if $appConfig.custom_logo_url}
                    <img src={$appConfig.custom_logo_url} alt="Logo" style="height: 25px;" />
                {:else}
                    <span class="d-sm-none"><Logo markOnly height={26} /></span>
                    <span class="d-none d-sm-block"><Logo height={25} /></span>
                {/if}
            </a>
            {#if $appConfig.test_list_enabled}
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="btn btn-sm btn-link btn-nav-tool" href={resolve("history")}
                            ><i class="bi bi-clock-history me-1"></i>History</a
                        >
                    </li>
                </ul>
            {/if}
            <div class="d-flex align-items-center gap-2 ms-auto">
                <span class="d-none d-md-inline navbar-text text-body-secondary small">
                    Open-Source Email Deliverability Tester
                </span>
                <button
                    class="btn btn-sm btn-link btn-nav-tool"
                    onclick={toggleTheme}
                    aria-label="Toggle theme"
                    title="Toggle theme"
                >
                    <i class="bi bi-{$theme === 'light' ? 'moon-stars-fill' : 'sun-fill'}"></i>
                </button>
            </div>
        </div>
    </nav>

    <main class="flex-grow-1 d-flex flex-column">
        {@render children?.()}
    </main>

    <footer
        id="footer-classic"
        class="px-4 px-md-5 py-2 d-flex flex-wrap justify-content-between align-items-center gap-2"
    >
        <a
            class="footer-brand-link d-inline-flex align-items-center gap-2 fw-medium"
            href="https://happydeliver.org/"
            target="_blank"
            rel="noopener"
        >
            <Logo markOnly height={14} />
            Powered by HappyDeliver
        </a>
        <ul class="footer-nav d-flex list-unstyled mb-0">
            <li>
                <a
                    class="d-inline-flex align-items-center gap-2"
                    href="https://git.happydomain.org/happydeliver/-/blob/master/api/openapi.yaml?ref_type=heads"
                    target="_blank"
                    rel="noopener"
                >
                    <i class="bi bi-code-slash"></i>
                    API
                </a>
            </li>
            <li>
                <a
                    class="d-inline-flex align-items-center gap-2"
                    href="https://git.happydomain.org/happydeliver"
                    target="_blank"
                    rel="noopener"
                >
                    <i class="bi bi-git"></i>
                    Git
                </a>
            </li>
            <li>
                <a
                    class="d-inline-flex align-items-center gap-2"
                    href="https://feedback.happydeliver.org/"
                    target="_blank"
                    rel="noopener"
                >
                    <i class="bi bi-lightbulb"></i>
                    Feedback
                </a>
            </li>
        </ul>
    </footer>

    <footer id="footer-happydomain" class="d-none pt-5 pb-3">
        <div class="container">
            <div class="row row-cols-1 row-cols-md-2 row-cols-lg-4 g-4 mb-4">
                <div class="col footer-brand-col">
                    <div class="footer-logo mb-3">
                        <Logo color="var(--footer-fg)" />
                    </div>
                    <p class="footer-tagline mb-0">
                        Open-source email deliverability tester. Check your SPF, DKIM, DMARC and
                        more before you hit send.
                    </p>
                    <div class="footer-social d-flex flex-wrap gap-2 mt-3">
                        <a
                            href="https://framagit.org/happyDomain/happydeliver"
                            target="_blank"
                            rel="noopener"
                            title="GitLab"
                            aria-label="Visit our GitLab repository"
                        >
                            <i class="bi bi-gitlab"></i>
                        </a>
                        <a
                            href="https://github.com/happyDomain/happydeliver"
                            target="_blank"
                            rel="noopener"
                            title="GitHub"
                            aria-label="Visit our GitHub repository"
                        >
                            <i class="bi bi-github"></i>
                        </a>
                        <a
                            href="https://floss.social/@happyDomain"
                            target="_blank"
                            rel="noopener"
                            title="Mastodon"
                            aria-label="Follow us on Mastodon"
                        >
                            <i class="bi bi-mastodon"></i>
                        </a>
                        <a
                            href="https://feedback.happydeliver.org/"
                            target="_blank"
                            rel="noopener"
                            title="Feedback"
                            aria-label="Share your feedback"
                        >
                            <i class="bi bi-lightbulb-fill"></i>
                        </a>
                    </div>
                </div>
                <div class="col">
                    <h4 class="footer-heading text-uppercase fw-semibold mb-3">Product</h4>
                    <ul class="footer-links list-unstyled d-flex flex-column gap-2 mb-0">
                        <li><a href="{resolve('/')}#features">Features</a></li>
                        <li>
                            <a
                                href="https://github.com/happyDomain/happydeliver/releases"
                                target="_blank"
                                rel="noopener">Download</a
                            >
                        </li>
                        <li>
                            <a
                                href="https://git.happydomain.org/happydeliver/-/blob/master/api/openapi.yaml?ref_type=heads"
                                target="_blank"
                                rel="noopener">API</a
                            >
                        </li>
                    </ul>
                </div>
                <div class="col">
                    <h4 class="footer-heading text-uppercase fw-semibold mb-3">Our association</h4>
                    <ul class="footer-links list-unstyled d-flex flex-column gap-2 mb-0">
                        <li>
                            <a
                                href="https://www.happydomain.org/en/who-we-are/"
                                target="_blank"
                                rel="noopener"
                            >
                                About us
                            </a>
                        </li>
                        <li>
                            <a
                                href="https://www.happydomain.org/en/community/"
                                target="_blank"
                                rel="noopener"
                            >
                                Contact
                            </a>
                        </li>
                        <li>
                            <a
                                href="https://www.happydomain.org/en/legal-notice/"
                                target="_blank"
                                rel="noopener"
                            >
                                Legal notice
                            </a>
                        </li>
                    </ul>
                </div>
                <div class="col">
                    <h4 class="footer-heading text-uppercase fw-semibold mb-3">Resources</h4>
                    <ul class="footer-links list-unstyled d-flex flex-column gap-2 mb-0">
                        <li>
                            <a
                                href="https://git.happydomain.org/happydeliver"
                                target="_blank"
                                rel="noopener"
                            >
                                Source code
                            </a>
                        </li>
                        <li>
                            <a
                                href="https://github.com/happyDomain/happydeliver/"
                                target="_blank"
                                rel="noopener"
                            >
                                GitHub
                            </a>
                        </li>
                        <li>
                            <a
                                href="https://feedback.happydeliver.org/"
                                target="_blank"
                                rel="noopener"
                            >
                                Feedback
                            </a>
                        </li>
                    </ul>
                </div>
            </div>
            <div
                class="footer-bottom pt-3 d-flex flex-wrap justify-content-between align-items-center gap-2"
            >
                <span class="footer-bottom-text">
                    © {new Date().getFullYear()} HappyDomain. Powered by HappyDeliver.
                </span>
                <a
                    class="footer-git-link"
                    href="https://git.happydomain.org/happydeliver"
                    target="_blank"
                    rel="noopener">Free & open-source software</a
                >
            </div>
        </div>
    </footer>
</div>

<style>
    /* Utility links read like nav items, not like hyperlinks. */
    :global(#nav .btn-nav-tool) {
        color: var(--hd-fg-2);
        font-weight: 600;
        text-decoration: none;
    }
    :global(#nav .btn-nav-tool:hover),
    :global(#nav .btn-nav-tool:focus-visible) {
        color: var(--bs-body-color);
        background-color: var(--hd-bg-overlay);
    }

    footer a {
        text-decoration: none;
    }

    /* Footers are always a band of brand Black, in both colour modes, so
       their colours are pinned instead of following the theme. */
    footer {
        --footer-fg: var(--hd-base-3);
        background-color: var(--hd-black);
        color: var(--footer-fg);
    }

    #footer-classic {
        font-size: 0.85rem;
    }

    #footer-happydomain {
        /* Footer is always a dark band (all child text is hardcoded light),
           so pin its colors instead of using theme-reactive utilities. */
        background-color: var(--hd-black);
        color: var(--footer-fg);
    }

    .footer-brand-link {
        color: color-mix(in srgb, var(--footer-fg) 70%, transparent);
        transition: color 0.2s;
    }

    .footer-brand-link:hover {
        color: var(--footer-fg);
    }

    .footer-nav li {
        display: flex;
        align-items: center;
    }

    .footer-nav li:not(:last-child)::after {
        content: "";
        width: 1px;
        height: 1rem;
        margin: 0 0.75rem;
        background-color: color-mix(in srgb, var(--footer-fg) 20%, transparent);
    }

    .footer-nav a {
        color: color-mix(in srgb, var(--footer-fg) 70%, transparent);
        transition: color 0.2s;
    }

    .footer-nav a:hover {
        color: var(--footer-fg);
    }

    .footer-nav a i {
        opacity: 0.7;
    }

    .footer-tagline {
        font-size: 0.8rem;
        color: color-mix(in srgb, var(--footer-fg) 50%, transparent);
        line-height: 1.55;
        max-width: 260px;
    }

    .footer-heading {
        font-size: 0.7rem;
        letter-spacing: 0.1em;
        color: color-mix(in srgb, var(--footer-fg) 45%, transparent);
    }

    .footer-links a {
        color: color-mix(in srgb, var(--footer-fg) 70%, transparent);
        font-size: 0.875rem;
        text-decoration: none;
        transition: color 0.2s;
    }

    .footer-links a:hover {
        color: var(--footer-fg);
    }

    .footer-social a {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 32px;
        height: 32px;
        border: 1px solid color-mix(in srgb, var(--footer-fg) 20%, transparent);
        border-radius: 6px;
        color: color-mix(in srgb, var(--footer-fg) 60%, transparent);
        text-decoration: none;
        font-size: 0.9rem;
        transition:
            color 0.2s,
            border-color 0.2s,
            background-color 0.2s;
    }

    .footer-social a:hover {
        color: var(--footer-fg);
        border-color: color-mix(in srgb, var(--footer-fg) 50%, transparent);
        background-color: color-mix(in srgb, var(--footer-fg) 8%, transparent);
    }

    .footer-bottom {
        border-top: 1px solid color-mix(in srgb, var(--footer-fg) 12%, transparent);
    }

    .footer-bottom-text {
        font-size: 0.75rem;
        color: color-mix(in srgb, var(--footer-fg) 40%, transparent);
    }

    .footer-git-link {
        font-size: 0.75rem;
        color: color-mix(in srgb, var(--footer-fg) 40%, transparent);
        text-decoration: none;
        transition: color 0.2s;
    }

    .footer-git-link:hover {
        color: color-mix(in srgb, var(--footer-fg) 80%, transparent);
    }
</style>
