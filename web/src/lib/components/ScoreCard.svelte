<script lang="ts">
    import type { ScoreSummary } from "$lib/api/types.gen";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface Props {
        grade: string;
        score: number;
        summary?: ScoreSummary;
    }

    let { grade, score, summary }: Props = $props();

    function getScoreLabel(score: number): string {
        if (score >= 90) return "Excellent";
        if (score >= 70) return "Good";
        if (score >= 50) return "Fair";
        if (score >= 30) return "Poor";
        return "Critical";
    }
</script>

<div class="card shadow-lg bg-white">
    <div class="card-body p-5 text-center">
        <div class="mb-3">
            <GradeDisplay {grade} {score} size="large" />
        </div>
        <h3 class="fw-bold mb-2">{getScoreLabel(score)}</h3>
        <p class="text-muted mb-4">Overall Deliverability Score</p>

        {#if summary}
            <div class="row g-3 text-start">
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <GradeDisplay grade={summary.dns_grade} score={summary.dns_score} />
                        <small class="text-muted d-block">DNS</small>
                    </div>
                </div>
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <GradeDisplay grade={summary.authentication_grade} score={summary.authentication_score} />
                        <small class="text-muted d-block">Authentication</small>
                    </div>
                </div>
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <GradeDisplay grade={summary.blacklist_grade} score={summary.blacklist_score} />
                        <small class="text-muted d-block">Blacklists</small>
                    </div>
                </div>
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <GradeDisplay grade={summary.header_grade} score={summary.header_score} />
                        <small class="text-muted d-block">Headers</small>
                    </div>
                </div>
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <GradeDisplay grade={summary.spam_grade} score={summary.spam_score} />
                        <small class="text-muted d-block">Spam Score</small>
                    </div>
                </div>
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <GradeDisplay grade={summary.content_grade} score={summary.content_score} />
                        <small class="text-muted d-block">Content</small>
                    </div>
                </div>
            </div>
        {/if}
    </div>
</div>
