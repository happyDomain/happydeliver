<script lang="ts">
    interface Props {
        grade?: string;
        score?: number;
        size?: "inline" | "small" | "medium" | "large";
    }

    let { grade, score, size = "medium" }: Props = $props();

    // Gradient from green (A) to red (F), see the --hd-grade-* tokens.
    function getGradeColor(grade?: string): string {
        const baseLetter = grade?.charAt(0).toLowerCase();
        if (baseLetter && "abcdef".includes(baseLetter)) return `var(--hd-grade-${baseLetter})`;
        return "var(--hd-grade-none)";
    }

    function getSizeClass(size: "inline" | "small" | "medium" | "large"): string {
        if (size === "inline") return "fw-bold";
        if (size === "small") return "fs-4";
        if (size === "large") return "display-1";
        return "fs-2";
    }
</script>

<strong class={getSizeClass(size)} style="color: {getGradeColor(grade)}; font-weight: 700;">
    {#if grade}
        {grade}
    {:else}
        {score}%
    {/if}
</strong>

<style>
    strong {
        transition: color 0.3s ease;
    }
</style>
