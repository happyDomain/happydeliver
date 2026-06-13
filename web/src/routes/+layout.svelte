<script lang="ts">
    import "bootstrap-icons/font/bootstrap-icons.css";
    import "bootstrap/dist/css/bootstrap.min.css";
    import "../app.css";

    import favicon from "$lib/assets/favicon.svg";

    import Logo from "$lib/components/Logo.svelte";
    import { appConfig } from "$lib/stores/config";
    import { theme } from "$lib/stores/theme";
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
    <nav class="navbar navbar-expand-lg navbar-light shadow-sm">
        <div class="container">
            <a class="navbar-brand fw-bold" href="/">
                {#if $appConfig.custom_logo_url}
                    <img src={$appConfig.custom_logo_url} alt="Logo" style="height: 25px;" />
                {:else}
                    <i class="bi bi-envelope-check me-2"></i>
                    <Logo color={$theme === "light" ? "black" : "white"} />
                {/if}
            </a>
            {#if $appConfig.test_list_enabled}
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/history/">
                            <i class="bi bi-clock-history me-1"></i>
                            History
                        </a>
                    </li>
                </ul>
            {/if}
            <div class="d-flex align-items-center">
                <span class="d-none d-md-inline navbar-text text-primary small">
                    Open-Source Email Deliverability Tester
                </span>
                <button
                    class="btn btn-link ms-auto {$theme == 'light' ? 'text-dark' : 'text-light'}"
                    onclick={toggleTheme}
                    aria-label="Toggle theme"
                    title="Toggle theme"
                >
                    <i class="bi bi-{$theme === 'light' ? 'moon-stars-fill' : 'sun-fill'}"></i>
                </button>
            </div>
        </div>
    </nav>

    <main class="flex-grow-1">
        {@render children?.()}
    </main>

    <footer
        id="footer-classic"
        class="px-4 px-md-5 py-2 d-flex flex-wrap justify-content-between align-items-center gap-2"
    >
        <a class="footer-brand-link" href="https://happydeliver.org/" target="_blank" rel="noopener">
            <i class="bi bi-envelope-check"></i>
            Powered by happyDeliver
        </a>
        <ul class="d-flex footer-nav">
            <li>
                <a
                    href="https://git.happydomain.org/happydeliver/-/blob/master/api/openapi.yaml?ref_type=heads"
                    target="_blank"
                    rel="noopener"
                >
                    <i class="bi bi-code-slash"></i>
                    API
                </a>
            </li>
            <li>
                <a href="https://git.happydomain.org/happydeliver" target="_blank" rel="noopener">
                    <i class="bi bi-git"></i>
                    Git
                </a>
            </li>
            <li>
                <a href="https://feedback.happydeliver.org/" target="_blank" rel="noopener">
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
                        <Logo color="white" />
                    </div>
                    <p class="footer-tagline">
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
                    <h4 class="footer-heading">Product</h4>
                    <ul class="footer-links">
                        <li><a href="/#features">Features</a></li>
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
                    <h4 class="footer-heading">Our association</h4>
                    <ul class="footer-links">
                        <li>
                            <a href="https://www.happydomain.org/en/who-we-are/" target="_blank" rel="noopener">
                                About us
                            </a>
                        </li>
                        <li>
                            <a href="https://www.happydomain.org/en/community/" target="_blank" rel="noopener">
                                Contact
                            </a>
                        </li>
                        <li>
                            <a href="https://www.happydomain.org/en/legal-notice/" target="_blank" rel="noopener">
                                Legal notice
                            </a>
                        </li>
                    </ul>
                </div>
                <div class="col">
                    <h4 class="footer-heading">Resources</h4>
                    <ul class="footer-links">
                        <li>
                            <a href="https://git.happydomain.org/happydeliver" target="_blank" rel="noopener">
                                Source code
                            </a>
                        </li>
                        <li>
                            <a href="https://github.com/happyDomain/happydeliver/" target="_blank" rel="noopener">
                                GitHub
                            </a>
                        </li>
                        <li>
                            <a href="https://feedback.happydeliver.org/" target="_blank" rel="noopener">
                                Feedback
                            </a>
                        </li>
                    </ul>
                </div>
            </div>
            <div class="footer-bottom pt-3 d-flex flex-wrap justify-content-between align-items-center gap-2">
                <span class="footer-bottom-text">
                    © {new Date().getFullYear()} happyDomain — Powered by happyDeliver
                </span>
                <a
                    class="footer-git-link"
                    href="https://git.happydomain.org/happydeliver"
                    target="_blank"
                    rel="noopener"
                >
                    Free &amp; open-source software
                </a>
            </div>
        </div>
    </footer>
</div>

<style>
    footer a {
        text-decoration: none;
    }

    #footer-classic {
        font-size: 0.85rem;
        /* Footer is always a dark band, so pin its colors instead of
           using theme-reactive utilities. */
        background-color: #212529;
        color: #f8f9fa;
    }

    .footer-brand-link {
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
        font-weight: 500;
        color: rgba(255, 255, 255, 0.7);
        transition: color 0.2s;
    }

    .footer-brand-link:hover {
        color: white;
    }

    .footer-nav {
        list-style: none;
        padding: 0;
        margin: 0;
        gap: 0;
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
        background-color: rgba(255, 255, 255, 0.2);
    }

    .footer-nav a {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        color: rgba(255, 255, 255, 0.7);
        transition: color 0.2s;
    }

    .footer-nav a:hover {
        color: white;
    }

    .footer-nav a i {
        opacity: 0.7;
    }

    #footer-happydomain {
        /* Footer is always a dark band (all child text is hardcoded white),
           so pin its colors instead of using theme-reactive utilities. */
        background-color: #212529;
        color: #f8f9fa;
    }

    .footer-tagline {
        font-size: 0.8rem;
        color: rgba(255, 255, 255, 0.5);
        line-height: 1.55;
        max-width: 260px;
        margin-bottom: 0;
    }

    .footer-heading {
        font-size: 0.7rem;
        font-weight: 600;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: rgba(255, 255, 255, 0.45);
        margin-bottom: 1rem;
    }

    .footer-links {
        list-style: none;
        padding: 0;
        display: flex;
        flex-direction: column;
        gap: 8px;
        margin: 0;
    }

    .footer-links a {
        color: rgba(255, 255, 255, 0.7);
        font-size: 0.875rem;
        text-decoration: none;
        transition: color 0.2s;
    }

    .footer-links a:hover {
        color: white;
    }

    .footer-social a {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 32px;
        height: 32px;
        border: 1px solid rgba(255, 255, 255, 0.2);
        border-radius: 6px;
        color: rgba(255, 255, 255, 0.6);
        text-decoration: none;
        font-size: 0.9rem;
        transition:
            color 0.2s,
            border-color 0.2s,
            background-color 0.2s;
    }

    .footer-social a:hover {
        color: white;
        border-color: rgba(255, 255, 255, 0.5);
        background-color: rgba(255, 255, 255, 0.08);
    }

    .footer-bottom {
        border-top: 1px solid rgba(255, 255, 255, 0.12);
    }

    .footer-bottom-text {
        font-size: 0.75rem;
        color: rgba(255, 255, 255, 0.4);
    }

    .footer-git-link {
        font-size: 0.75rem;
        color: rgba(255, 255, 255, 0.4);
        text-decoration: none;
        transition: color 0.2s;
    }

    .footer-git-link:hover {
        color: rgba(255, 255, 255, 0.8);
    }
</style>
