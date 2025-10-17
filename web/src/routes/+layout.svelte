<script lang="ts">
    import "bootstrap/dist/css/bootstrap.min.css";
    import "bootstrap-icons/font/bootstrap-icons.css";
    import "../app.css";
    interface Props {
        children?: import("svelte").Snippet;
    }

    let { children }: Props = $props();
</script>

<div class="min-vh-100 d-flex flex-column">
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary shadow-sm">
        <div class="container">
            <a class="navbar-brand fw-bold" href="/">
                <i class="bi bi-envelope-check me-2"></i>
                happyDeliver
            </a>
            <span class="navbar-text text-white-50 small">
                Open-Source Email Deliverability Tester
            </span>
        </div>
    </nav>

    <main class="flex-grow-1">
        {@render children?.()}
    </main>

    <footer class="bg-dark text-light py-4">
        <div class="container text-center">
            <p class="mb-1">
                <small class="d-flex justify-content-center gap-2">
                    Open-Source Email Deliverability Testing Platform
                    <span class="mx-1">&bull;</span>
                    <a
                        href="https://github.com/happyDomain/happyDeliver"
                        class="text-decoration-none"
                    >
                        <i class="bi bi-github"></i> GitHub
                    </a>
                    <a
                        href="https://framagit.com/happyDomain/happyDeliver"
                        class="text-decoration-none"
                    >
                        <i class="bi bi-gitlab"></i> GitLab
                    </a>
                </small>
            </p>
        </div>
    </footer>
</div>
