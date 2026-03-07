<script lang="ts">
    import type { BlacklistCheck } from "$lib/api/types.gen";
    import { theme } from "$lib/stores/theme";

    interface Props {
        whitelists: Record<string, BlacklistCheck[]>;
    }

    let { whitelists }: Props = $props();
</script>

<div class="card shadow-sm" id="dnswl-details">
    <div class="card-header" class:bg-white={$theme === "light"} class:bg-dark={$theme !== "light"}>
        <h4 class="mb-0 d-flex justify-content-between align-items-center">
            <span>
                <i class="bi bi-shield-check me-2"></i>
                Whitelist Checks
            </span>
            <span class="badge bg-info text-white">Informational</span>
        </h4>
    </div>
    <div class="card-body">
        <p class="text-muted small mb-3">
            DNS whitelists identify trusted senders. Being listed here is a positive signal, but has
            no impact on the overall score.
        </p>

        <div class="row row-cols-1 row-cols-lg-2">
            {#each Object.entries(whitelists) as [ip, checks]}
                <div class="col mb-3">
                    <h5 class="text-muted">
                        <i class="bi bi-hdd-network me-1"></i>
                        {ip}
                    </h5>
                    <table class="table table-sm table-striped table-hover mb-0">
                        <tbody>
                            {#each checks as check}
                                <tr>
                                    <td title={check.response || "-"}>
                                        <span
                                            class="badge"
                                            class:bg-success={check.listed}
                                            class:bg-dark={check.error}
                                            class:bg-secondary={!check.listed && !check.error}
                                        >
                                            {check.error
                                                ? "Error"
                                                : check.listed
                                                  ? "Listed"
                                                  : "Not listed"}
                                        </span>
                                    </td>
                                    <td><code>{check.rbl}</code></td>
                                </tr>
                            {/each}
                        </tbody>
                    </table>
                </div>
            {/each}
        </div>
    </div>
</div>
