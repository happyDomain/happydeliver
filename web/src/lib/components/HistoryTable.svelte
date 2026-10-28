<script lang="ts">
    import { resolve } from "$app/paths";

    import type { TestSummary } from "#lib/api/types.gen.js";
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

<div class="table-responsive">
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
            {#each tests as test (test.test_id)}
                {@const href = resolve("/test/[test]", { test: test.test_id })}
                <tr>
                    <td class="p-0">
                        <a
                            {href}
                            class="d-block p-2 ps-4 text-reset text-decoration-none"
                            tabindex="-1"
                            aria-label="Open test"
                        >
                            <GradeDisplay grade={test.grade} size="small" />
                        </a>
                    </td>
                    <td class="p-0">
                        <a {href} class="d-block p-2 text-reset text-decoration-none" tabindex="-1">
                            <span class="badge bg-secondary">{test.score}%</span>
                        </a>
                    </td>
                    <td class="p-0">
                        <a {href} class="d-block p-2 text-reset text-decoration-none">
                            {#if test.from_domain}
                                <code>{test.from_domain}</code>
                            {:else}
                                <span class="text-muted">-</span>
                            {/if}
                        </a>
                    </td>
                    <td class="p-0">
                        <a {href} class="d-block p-2 text-muted text-decoration-none" tabindex="-1">
                            {formatDate(test.created_at)}
                        </a>
                    </td>
                    <td class="p-0">
                        <a
                            {href}
                            class="d-block p-2 text-reset text-decoration-none"
                            tabindex="-1"
                            aria-hidden="true"
                        >
                            <i class="bi bi-chevron-right text-muted"></i>
                        </a>
                    </td>
                </tr>
            {/each}
        </tbody>
    </table>
</div>
