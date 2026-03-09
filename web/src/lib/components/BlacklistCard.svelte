<script lang="ts">
    import type { BlacklistCheck } from "$lib/api/types.gen";
    import { getScoreColorClass } from "$lib/score";
    import { theme } from "$lib/stores/theme";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        blacklists: Record<string, BlacklistCheck[]>;
        blacklistGrade?: string;
        blacklistScore?: number;
    }

    let { blacklists, blacklistGrade, blacklistScore }: Props = $props();
</script>

<div class="card shadow-sm" id="rbl-details">
    <div class="card-header" class:bg-white={$theme === "light"} class:bg-dark={$theme !== "light"}>
        <h4 class="mb-0 d-flex flex-wrap justify-content-between align-items-center">
            <span>
                <i class="bi bi-shield-exclamation me-2"></i>
                Blacklist Checks
            </span>
            <span>
                {#if blacklistScore !== undefined}
                    <span class="badge bg-{getScoreColorClass(blacklistScore)}">
                        {blacklistScore}%
                    </span>
                {/if}
                {#if blacklistGrade !== undefined}
                    <GradeDisplay grade={blacklistGrade} size="small" />
                {/if}
            </span>
        </h4>
    </div>
    <div class="card-body">
        <div class="row row-cols-1 row-cols-lg-2 overflow-auto">
            {#each Object.entries(blacklists) as [ip, checks]}
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
                                            class="badge {check.listed
                                                ? 'bg-danger'
                                                : check.error
                                                  ? 'bg-dark'
                                                  : 'bg-success'}"
                                        >
                                            {check.error
                                                ? "Error"
                                                : check.listed
                                                  ? "Listed"
                                                  : "Clean"}
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
