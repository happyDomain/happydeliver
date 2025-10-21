<script lang="ts">
    import type { ScoreSummary } from "$lib/api/types.gen";

    interface Props {
        grade: string;
        score: number;
        summary?: ScoreSummary;
    }

    let { grade, score, summary }: Props = $props();

    function getScoreClass(score: number): string {
        if (score >= 90) return "score-excellent";
        if (score >= 70) return "score-good";
        if (score >= 50) return "score-warning";
        if (score >= 30) return "score-poor";
        return "score-bad";
    }

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
        <h1 class="display-1 fw-bold mb-3 {getScoreClass(score)}">
            {grade}
        </h1>
        <h3 class="fw-bold mb-2">{getScoreLabel(score)}</h3>
        <p class="text-muted mb-4">Overall Deliverability Score</p>

        {#if summary}
            <div class="row g-3 text-start">
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <strong
                            class="fs-2"
                            class:text-success={summary.authentication_score >= 100}
                            class:text-warning={summary.authentication_score < 100 &&
                                summary.authentication_score >= 50}
                            class:text-danger={summary.authentication_score < 50}
                        >
                            {summary.authentication_score}%
                        </strong>
                        <small class="text-muted d-block">Authentication</small>
                    </div>
                </div>
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <strong
                            class="fs-2"
                            class:text-success={summary.spam_score >= 100}
                            class:text-warning={summary.spam_score < 100 && summary.spam_score >= 50}
                            class:text-danger={summary.spam_score < 50}
                        >
                            {summary.spam_score}%
                        </strong>
                        <small class="text-muted d-block">Spam Score</small>
                    </div>
                </div>
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <strong
                            class="fs-2"
                            class:text-success={summary.blacklist_score >= 100}
                            class:text-warning={summary.blacklist_score < 100 &&
                                summary.blacklist_score >= 50}
                            class:text-danger={summary.blacklist_score < 50}
                        >
                            {summary.blacklist_score}%
                        </strong>
                        <small class="text-muted d-block">Blacklists</small>
                    </div>
                </div>
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <strong
                            class="fs-2"
                            class:text-success={summary.content_score >= 100}
                            class:text-warning={summary.content_score < 100 &&
                                summary.content_score >= 50}
                            class:text-danger={summary.content_score < 50}
                        >
                            {summary.content_score}%
                        </strong>
                        <small class="text-muted d-block">Content</small>
                    </div>
                </div>
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <strong
                            class="fs-2"
                            class:text-success={summary.header_score >= 100}
                            class:text-warning={summary.header_score < 100 &&
                                summary.header_score >= 50}
                            class:text-danger={summary.header_score < 50}
                        >
                            {summary.header_score}%
                        </strong>
                        <small class="text-muted d-block">Headers</small>
                    </div>
                </div>
            </div>
        {/if}
    </div>
</div>
