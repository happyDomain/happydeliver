<script lang="ts">
    import type { ScoreSummary } from "$lib/api/types.gen";

    interface Props {
        score: number;
        summary?: ScoreSummary;
    }

    let { score, summary }: Props = $props();

    function getScoreClass(score: number): string {
        if (score >= 9) return "score-excellent";
        if (score >= 7) return "score-good";
        if (score >= 5) return "score-warning";
        if (score >= 3) return "score-poor";
        return "score-bad";
    }

    function getScoreLabel(score: number): string {
        if (score >= 9) return "Excellent";
        if (score >= 7) return "Good";
        if (score >= 5) return "Fair";
        if (score >= 3) return "Poor";
        return "Critical";
    }
</script>

<div class="card shadow-lg bg-white">
    <div class="card-body p-5 text-center">
        <h1 class="display-1 fw-bold mb-3 {getScoreClass(score)}">
            {score.toFixed(1)}/10
        </h1>
        <h3 class="fw-bold mb-2">{getScoreLabel(score)}</h3>
        <p class="text-muted mb-4">Overall Deliverability Score</p>

        {#if summary}
            <div class="row g-3 text-start">
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <strong
                            class="fs-2"
                            class:text-success={summary.authentication_score >= 3}
                            class:text-warning={summary.authentication_score < 3 &&
                                summary.authentication_score >= 1.5}
                            class:text-danger={summary.authentication_score < 1.5}
                        >
                            {summary.authentication_score.toFixed(1)}/3
                        </strong>
                        <small class="text-muted d-block">Authentication</small>
                    </div>
                </div>
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <strong
                            class="fs-2"
                            class:text-success={summary.spam_score >= 2}
                            class:text-warning={summary.spam_score < 2 && summary.spam_score >= 1}
                            class:text-danger={summary.spam_score < 1}
                        >
                            {summary.spam_score.toFixed(1)}/2
                        </strong>
                        <small class="text-muted d-block">Spam Score</small>
                    </div>
                </div>
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <strong
                            class="fs-2"
                            class:text-success={summary.blacklist_score >= 2}
                            class:text-warning={summary.blacklist_score < 2 &&
                                summary.blacklist_score >= 1}
                            class:text-danger={summary.blacklist_score < 1}
                        >
                            {summary.blacklist_score.toFixed(1)}/2
                        </strong>
                        <small class="text-muted d-block">Blacklists</small>
                    </div>
                </div>
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <strong
                            class="fs-2"
                            class:text-success={summary.content_score >= 2}
                            class:text-warning={summary.content_score < 2 &&
                                summary.content_score >= 1}
                            class:text-danger={summary.content_score < 1}
                        >
                            {summary.content_score.toFixed(1)}/2
                        </strong>
                        <small class="text-muted d-block">Content</small>
                    </div>
                </div>
                <div class="col-md-6 col-lg">
                    <div class="p-2 bg-light rounded text-center">
                        <strong
                            class="fs-2"
                            class:text-success={summary.header_score >= 1}
                            class:text-warning={summary.header_score < 1 &&
                                summary.header_score >= 0.5}
                            class:text-danger={summary.header_score < 0.5}
                        >
                            {summary.header_score.toFixed(1)}/1
                        </strong>
                        <small class="text-muted d-block">Headers</small>
                    </div>
                </div>
            </div>
        {/if}
    </div>
</div>
