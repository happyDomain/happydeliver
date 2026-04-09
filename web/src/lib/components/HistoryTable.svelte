<script lang="ts">
    import { goto } from "$app/navigation";

    import type { TestSummary } from "$lib/api/types.gen";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        tests: TestSummary[];
    }

    let { tests }: Props = $props();

    function formatDate(dateStr: string): string {
        const date = new Date(dateStr);
        return date.toLocaleDateString(undefined, {
            year: "numeric",
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
        });
    }
</script>

<div class="table-responsive shadow-sm">
    <table class="table table-hover mb-0 align-middle">
        <thead>
            <tr>
                <th class="ps-4" style="width: 80px;">Grade</th>
                <th style="width: 80px;">Score</th>
                <th>Domain</th>
                <th>Date</th>
                <th style="width: 50px;"></th>
            </tr>
        </thead>
        <tbody>
            {#each tests as test}
                <tr class="cursor-pointer" onclick={() => goto(`/test/${test.test_id}`)}>
                    <td class="ps-4">
                        <GradeDisplay grade={test.grade} size="small" />
                    </td>
                    <td>
                        <span class="badge bg-secondary">{test.score}%</span>
                    </td>
                    <td>
                        {#if test.from_domain}
                            <code>{test.from_domain}</code>
                        {:else}
                            <span class="text-muted">-</span>
                        {/if}
                    </td>
                    <td class="text-muted">
                        {formatDate(test.created_at)}
                    </td>
                    <td>
                        <i class="bi bi-chevron-right text-muted"></i>
                    </td>
                </tr>
            {/each}
        </tbody>
    </table>
</div>

<style>
    .cursor-pointer {
        cursor: pointer;
    }

    .cursor-pointer:hover td {
        background-color: var(--bs-tertiary-bg);
    }
</style>
