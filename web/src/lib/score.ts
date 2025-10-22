export function getScoreColorClass(percentage: number): string {
    if (percentage >= 85) return "success";
    if (percentage >= 50) return "warning";
    return "danger";
}
