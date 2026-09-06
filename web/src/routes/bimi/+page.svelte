<script lang="ts">
    import { goto } from "$app/navigation";
    import { resolve } from "$app/paths";

    let domain = $state("");
    let selector = $state("default");
    let localPart = $state("");
    let advancedOpen = $state(false);
    let error = $state<string | null>(null);

    const domainPattern =
        /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*$/;
    /* A selector becomes a label of the queried name, so it has to be one
       label: anything else would only produce a puzzling lookup failure. */
    const selectorPattern = /^[a-zA-Z0-9]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?$/;

    function handleSubmit() {
        error = null;

        const target = domain.trim().replace(/\.$/, "");
        if (!target) {
            error = "Please enter a domain name";
            return;
        }
        if (!domainPattern.test(target)) {
            error = "Please enter a valid domain name (e.g., example.com)";
            return;
        }

        const sel = selector.trim() || "default";
        if (!selectorPattern.test(sel)) {
            error =
                "A selector is a single DNS label: letters, digits, hyphens and underscores (e.g., default)";
            return;
        }

        const query: string[] = [];
        if (sel !== "default") query.push(`selector=${encodeURIComponent(sel)}`);
        if (localPart.trim()) query.push(`local_part=${encodeURIComponent(localPart.trim())}`);

        const path = resolve("/bimi/[domain]", { domain: target });
        // eslint-disable-next-line svelte/no-navigation-without-resolve -- resolved route above, with a query string appended
        goto(query.length > 0 ? `${path}?${query.join("&")}` : path);
    }

    function handleKeyPress(event: KeyboardEvent) {
        if (event.key === "Enter") {
            handleSubmit();
        }
    }
</script>

<svelte:head>
    <title>BIMI Checker - happyDeliver</title>
</svelte:head>

<div class="container py-5">
    <div class="row">
        <div class="col-lg-8 mx-auto">
            <!-- Header -->
            <div class="text-center mb-5">
                <h1 class="display-4 fw-bold mb-3">
                    <i class="bi bi-building-check me-2"></i>
                    Check Your BIMI Record
                </h1>
                <p class="lead text-muted">
                    Validate the Assertion Record a domain publishes, the logo it points at and the
                    Verified Mark Certificate that vouches for it &mdash; without sending a single
                    email.
                </p>
            </div>

            <!-- Input Form -->
            <div class="card shadow-lg border-0 mb-5">
                <div class="card-body p-5">
                    <h2 class="h5 mb-4">Enter Domain Name</h2>
                    <div class="input-group input-group-lg mb-3">
                        <span class="input-group-text bg-light">
                            <i class="bi bi-at"></i>
                        </span>
                        <input
                            type="text"
                            class="form-control"
                            placeholder="example.com"
                            bind:value={domain}
                            onkeypress={handleKeyPress}
                            autofocus
                        />
                        <button
                            class="btn btn-primary px-5"
                            onclick={handleSubmit}
                            disabled={!domain.trim()}
                        >
                            <i class="bi bi-search me-2"></i>
                            Check
                        </button>
                    </div>

                    <button
                        type="button"
                        class="btn btn-link btn-sm p-0 text-decoration-none"
                        aria-expanded={advancedOpen}
                        aria-controls="bimi-advanced"
                        onclick={() => (advancedOpen = !advancedOpen)}
                    >
                        <i
                            class="bi me-1"
                            class:bi-chevron-right={!advancedOpen}
                            class:bi-chevron-down={advancedOpen}
                        ></i>
                        Selector and sending address
                    </button>

                    <div id="bimi-advanced" class="row g-3 mt-1" class:d-none={!advancedOpen}>
                        <div class="col-md-6">
                            <label class="form-label small fw-semibold" for="bimi-selector">
                                Selector
                            </label>
                            <input
                                id="bimi-selector"
                                type="text"
                                class="form-control"
                                placeholder="default"
                                bind:value={selector}
                                onkeypress={handleKeyPress}
                            />
                            <div class="form-text">
                                The record is read at
                                <code
                                    >{selector.trim() || "default"}._bimi.{domain.trim() ||
                                        "example.com"}</code
                                >. Messages that carry no <code>BIMI-Selector</code> header use
                                <code>default</code>.
                            </div>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label small fw-semibold" for="bimi-local-part">
                                Sending address <span class="fw-normal text-muted">(optional)</span>
                            </label>
                            <div class="input-group">
                                <input
                                    id="bimi-local-part"
                                    type="text"
                                    class="form-control"
                                    placeholder="newsletter"
                                    bind:value={localPart}
                                    onkeypress={handleKeyPress}
                                />
                                <span class="input-group-text"
                                    >@{domain.trim() || "example.com"}</span
                                >
                            </div>
                            <div class="form-text">
                                Only the local-part. A record publishing an <code>lps=</code> tag serves
                                a different indicator per mailbox: fill this in to be shown the one that
                                sender actually gets.
                            </div>
                        </div>
                    </div>

                    {#if error}
                        <div class="alert alert-danger mt-3 mb-0" role="alert">
                            <i class="bi bi-exclamation-triangle me-2"></i>
                            {error}
                        </div>
                    {/if}
                </div>
            </div>

            <!-- Info Section -->
            <div class="row g-4 mb-4">
                <div class="col-md-6">
                    <div class="card h-100 border-0 bg-light">
                        <div class="card-body">
                            <h3 class="h6 mb-3">
                                <i class="bi bi-check-circle-fill text-success me-2"></i>
                                What's Checked
                            </h3>
                            <ul class="list-unstyled mb-0 small">
                                <li class="mb-2">
                                    <i class="bi bi-arrow-right me-2"></i>Assertion Record syntax
                                    and tags
                                </li>
                                <li class="mb-2">
                                    <i class="bi bi-arrow-right me-2"></i>DMARC policy at
                                    enforcement
                                </li>
                                <li class="mb-2">
                                    <i class="bi bi-arrow-right me-2"></i>Logo fetch over HTTPS
                                </li>
                                <li class="mb-2">
                                    <i class="bi bi-arrow-right me-2"></i>SVG Tiny Portable/Secure
                                    profile
                                </li>
                                <li class="mb-2">
                                    <i class="bi bi-arrow-right me-2"></i>Verified Mark Certificate
                                    chain and profile
                                </li>
                                <li class="mb-0">
                                    <i class="bi bi-arrow-right me-2"></i>Certified mark matching
                                    the published logo
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>

                <div class="col-md-6">
                    <div class="card h-100 border-0 bg-light">
                        <div class="card-body">
                            <h3 class="h6 mb-3">
                                <i class="bi bi-info-circle-fill text-primary me-2"></i>
                                What This Is Not
                            </h3>
                            <p class="small mb-2">
                                This checker reads the record straight from DNS, so it reports what
                                a receiver would find for that domain and selector. It says nothing
                                about a particular message: whether one actually passes DMARC, and
                                is therefore eligible for an indicator, depends on how it was sent.
                            </p>
                            <a href={resolve("/")} class="btn btn-sm btn-outline-primary">
                                <i class="bi bi-envelope-plus me-1"></i>
                                Test a Real Message
                            </a>
                            <a href={resolve("/domain")} class="btn btn-sm btn-outline-secondary">
                                <i class="bi bi-globe me-1"></i>
                                Test the Whole Domain
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
    .card {
        transition:
            transform 0.2s ease,
            box-shadow 0.2s ease;
    }

    .card:hover {
        transform: translateY(-2px);
        box-shadow: 0 0.5rem 1.5rem rgba(0, 0, 0, 0.1) !important;
    }

    .input-group-lg .form-control {
        font-size: 1.1rem;
    }
</style>
