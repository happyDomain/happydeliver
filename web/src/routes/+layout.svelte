<script lang="ts">
    import "bootstrap/dist/css/bootstrap.min.css";
    import "bootstrap-icons/font/bootstrap-icons.css";
    import "../app.css";

    import Logo from "$lib/components/Logo.svelte";

    interface Props {
        children?: import("svelte").Snippet;
    }

    let { children }: Props = $props();
</script>

<div class="min-vh-100 d-flex flex-column">
    <nav class="navbar navbar-expand-lg navbar-light shadow-sm">
        <div class="container">
            <a class="navbar-brand fw-bold" href="/">
                <i class="bi bi-envelope-check me-2"></i>
                <Logo />
            </a>
            <span class="d-none d-md-inline navbar-text text-primary small">
                Open-Source Email Deliverability Tester
            </span>
        </div>
    </nav>

    <main class="flex-grow-1">
        {@render children?.()}
    </main>

    <footer class="pt-3 pb-2 bg-dark text-light">
        <div class="container mb-4">
            <div class="row row-cols-1 row-cols-md-2 row-cols-lg-4">
                <div class="col">
                    <h3>
                        <Logo color="white" />
                    </h3>
                    <ul class="footer-links">
                        <li><a href="/#features">Features</a></li>
                        <li><a href="#">Download</a></li>
                        <li>
                            <a href="https://github.com/happyDomain/happydeliver/" target="_blank">
                                GitHub
                            </a>
                        </li>
                    </ul>
                </div>
                <div class="col">
                    <h3>Our association</h3>
                    <ul class="footer-links">
                        <li>
                            <a href="https://www.happydomain.org/en/who-we-are/" target="_blank">
                                About us
                            </a>
                        </li>
                        <li>
                            <a href="https://www.happydomain.org/en/community/" target="_blank">
                                Contact
                            </a>
                        </li>
                        <li>
                            <a href="https://www.happydomain.org/en/legal-notice/" target="_blank">
                                Legal notice
                            </a>
                        </li>
                    </ul>
                </div>
                <div class="col"></div>
                <div class="col">
                    <h3>Follow-us</h3>
                    <div
                        class="d-flex flex-wrap justify-content-between footer-links"
                        style="gap: .5em; font-size: 2em"
                    >
                        <a href="https://framagit.org/happyDomain/happydeliver" target="_blank">
                            <i class="bi bi-gitlab"></i>
                        </a>
                        <a href="https://github.com/happyDomain/happydeliver" target="_blank">
                            <i class="bi bi-github"></i>
                        </a>
                        <a href="https://feedback.happydomain.org/" target="_blank">
                            <i class="bi bi-lightbulb-fill"></i>
                        </a>
                        <a href="https://floss.social/@happyDomain" target="_blank">
                            <i class="bi bi-mastodon"></i>
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </footer>
</div>

<style>
    footer {
        border-top: 3px solid #9332bb;
    }

    .footer-links {
        list-style: none;
        padding: 0;
    }

    .footer-links li {
        margin-bottom: 12px;
    }

    .footer-links a {
        color: rgba(255, 255, 255, 0.7);
        text-decoration: none;
        transition: color 0.3s;
    }

    .footer-links a:hover {
        color: white;
    }
</style>
