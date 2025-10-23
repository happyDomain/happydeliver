<script lang="ts">
    interface Props {
        grade?: string;
        score: number;
        size?: "inline" | "small" | "medium" | "large";
    }

    let { grade, score, size = "medium" }: Props = $props();

    function getGradeColor(grade?: string): string {
        if (!grade) return "#6b7280"; // Gray for no grade

        const baseLetter = grade.charAt(0).toUpperCase();
        const modifier = grade.length > 1 ? grade.charAt(1) : "";

        // Gradient from green (A+) to red (F)
        switch (baseLetter) {
            case "A":
                if (modifier === "+") return "#22c55e"; // Bright green
                if (modifier === "-") return "#16a34a"; // Green
                return "#22c55e"; // Green
            case "B":
                if (modifier === "-") return "#65a30d"; // Darker lime
                return "#84cc16"; // Lime
            case "C":
                if (modifier === "-") return "#ca8a04"; // Darker yellow
                return "#eab308"; // Yellow
            case "D":
                return "#f97316"; // Orange
            case "E":
                return "#ea580c"; // Red
            case "F":
                return "#dc2626"; // Red
            default:
                return "#6b7280"; // Gray
        }
    }

    function getSizeClass(size: "inline" | "small" | "medium" | "large"): string {
        if (size === "inline") return "fw-bold";
        if (size === "small") return "fs-4";
        if (size === "large") return "display-1";
        return "fs-2";
    }
</script>

<strong
    class={getSizeClass(size)}
    style="color: {getGradeColor(grade)}; font-weight: 700;"
>
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
