<script lang="ts">
    import type { RBLCheck } from "$lib/api/types.gen";
    import { getScoreColorClass } from "$lib/score";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        blacklists: Record<string, RBLCheck[]>;
        blacklistGrade?: string;
        blacklistScore?: number;
    }

    let { blacklists, blacklistGrade, blacklistScore }: Props = $props();
</script>

<div class="card shadow-sm">
    <div class="card-header bg-white">
        <h4 class="mb-0 d-flex justify-content-between align-items-center">
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
        <div class="row row-cols-1 row-cols-lg-2">
            {#each Object.entries(blacklists) as [ip, checks]}
                <div class="col mb-3">
                    <h6 class="text-muted">
                        <i class="bi bi-hdd-network me-1"></i>
                        {ip}
                    </h6>
                    <div class="table-responsive">
                        <table class="table table-sm">
                            <thead>
                                <tr>
                                    <th>RBL</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {#each checks as check}
                                    <tr>
                                        <td><code>{check.rbl}</code></td>
                                        <td title={check.response || '-'}>
                                            <span class="badge {check.listed ? 'bg-danger' : check.error ? 'bg-dark' : 'bg-success'}">
                                                {check.error ? 'Error' : (check.listed ? 'Listed' : 'Clean')}
                                            </span>
                                        </td>
                                    </tr>
                                {/each}
                            </tbody>
                        </table>
                    </div>
                </div>
            {/each}
        </div>
    </div>
</div>
