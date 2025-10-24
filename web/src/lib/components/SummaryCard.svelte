<script lang="ts">
    import type { Report } from "$lib/api/types.gen";
    import GradeDisplay from "./GradeDisplay.svelte";

    interface TextSegment {
        text: string;
        highlight?: {
            color: "good" | "warning" | "danger";
            bold?: boolean;
        };
        link?: string;
    }

    interface Props {
        report: Report;
    }

    let { report }: Props = $props();

    function buildSummary(): TextSegment[] {
        const segments: TextSegment[] = [];

        // Email sender information
        const mailFrom = report.header_analysis?.headers?.from?.value || "an unknown sender";
        const hasDkim = report.authentication?.dkim && report.authentication.dkim.length > 0;
        const dkimPassed = hasDkim && report.authentication.dkim.some(d => d.result === "pass");

        segments.push({ text: "Received a " });
        segments.push({
            text: dkimPassed ? "DKIM-signed" : "non-DKIM-signed",
            highlight: { color: dkimPassed ? "good" : "danger", bold: true },
            link: "#authentication-dkim"
        });
        segments.push({ text: " email from " });
        segments.push({
            text: mailFrom,
            highlight: { emphasis: true }
        });

        // Server information and hops
        const receivedChain = report.header_analysis?.received_chain;
        if (receivedChain && receivedChain.length > 0) {
            const firstHop = receivedChain[0];
            const serverName = firstHop.from || firstHop.ip || "an unknown server";
            const hopCount = receivedChain.length;
            segments.push({ text: ", sent by " });
            segments.push({
                text: serverName,
                highlight: { monospace: true },
                link: "#header-details"
            });
            segments.push({ text: " after " });
            segments.push({
                text: `${hopCount-1} hop${hopCount-1 !== 1 ? "s" : ""}`,
                link: "#email-path"
            });
        }

        // Authentication status
        const spfResult = report.authentication?.spf?.result;
        const dmarcResult = report.authentication?.dmarc?.result;

        segments.push({ text: " which is " });
        if (spfResult === "pass" || dmarcResult === "pass") {
            segments.push({
                text: "authenticated",
                highlight: { color: "good", bold: true },
                link: "#authentication-details"
            });
            segments.push({ text: " to send email on behalf of " });
            segments.push({ text: report.header_analysis?.domain_alignment?.from_domain, highlight: {monospace: true} });
        } else if (spfResult && spfResult !== "none") {
            segments.push({
                text: "not authenticated",
                highlight: { color: "danger", bold: true },
                link: "#authentication-spf"
            });
            segments.push({ text: " (failed authentication checks)" });
        } else {
            segments.push({
                text: "not authenticated",
                highlight: { color: "warning", bold: true },
                link: "#authentication-details"
            });
            segments.push({ text: " (lacks proper authentication)" });
        }

        // SPF specific issues
        if (spfResult && spfResult !== "pass") {
            segments.push({ text: ". SPF check " });
            if (spfResult === "fail") {
                segments.push({
                    text: "failed",
                    highlight: { color: "danger", bold: true },
                    link: "#authentication-spf"
                });
                segments.push({ text: ", the sending server is not authorized to send mail for this domain" });
            } else if (spfResult === "softfail") {
                segments.push({
                    text: "soft-failed",
                    highlight: { color: "warning", bold: true },
                    link: "#authentication-spf"
                });
                segments.push({ text: ", the sending server may not be authorized" });
            } else if (spfResult === "temperror" || spfResult === "permerror") {
                segments.push({
                    text: "encountered an error",
                    highlight: { color: "warning", bold: true },
                    link: "#authentication-spf"
                });
                segments.push({ text: ", check your SPF record configuration" });
            } else if (spfResult === "none") {
                segments.push({ text: "Your domain has " });
                segments.push({
                    text: "no SPF record",
                    highlight: { color: "danger", bold: true },
                    link: "#dns-spf"
                });
                segments.push({ text: ", you should add one to specify which servers can send email on your behalf" });
            }
        }

        // IP Reverse DNS (iprev) check
        const iprevResult = report.authentication?.iprev;
        if (iprevResult) {
            segments.push({ text: ". Its reverse IP " });
            if (iprevResult.result === "pass") {
                segments.push({ text: "looks " });
                segments.push({
                    text: "good",
                    highlight: { color: "good", bold: true },
                    link: "#dns-ptr"
                });
            } else if (iprevResult.result === "fail") {
                segments.push({
                    text: "failed",
                    highlight: { color: "danger", bold: true },
                    link: "#dns-ptr"
                });
                segments.push({ text: " to pass the test" });
            } else {
                segments.push({ text: "returned " });
                segments.push({
                    text: iprevResult.result,
                    highlight: { color: "warning", bold: true },
                    link: "#dns-ptr"
                });
            }
        }

        // Blacklist status
        const blacklists = report.blacklists;
        if (blacklists && Object.keys(blacklists).length > 0) {
            const allChecks = Object.values(blacklists).flat();
            const listedCount = allChecks.filter(check => check.listed).length;

            segments.push({ text: ". Your server is " });
            if (listedCount > 0) {
                segments.push({
                    text: `blacklisted on ${listedCount} list${listedCount !== 1 ? "s" : ""}`,
                    highlight: { color: "danger", bold: true },
                    link: "#rbl-details"
                });
            } else {
                segments.push({
                    text: "not blacklisted",
                    highlight: { color: "good", bold: true },
                    link: "#rbl-details"
                });
            }
        }

        // Domain alignment
        const domainAlignment = report.header_analysis?.domain_alignment;
        if (domainAlignment) {
            segments.push({ text: ". Domain alignment is " });
            if (domainAlignment.aligned || domainAlignment.relaxed_aligned) {
                segments.push({
                    text: "good",
                    highlight: { color: "good", bold: true },
                    link: "#domain-alignment"
                });
                if (!domainAlignment.aligned) {
                    segments.push({ text: " using organizational domain" });
                }
            } else {
                segments.push({
                    text: "misaligned",
                    highlight: { color: "danger", bold: true },
                    link: "#domain-alignment"
                });
                segments.push({ text: ": " });
                segments.push({ text: "Return-Path", highlight: { monospace: true } });
                segments.push({ text: " is set to an address of " });
                segments.push({ text: report.header_analysis?.domain_alignment?.return_path_domain, highlight: { monospace: true } });
                segments.push({ text: ", you should " });
                segments.push({
                    text: "update it",
                    highlight: { bold: true },
                    link: "#domain-alignment"
                });
            }
        }

        // DMARC policy check
        const dmarcRecord = report.dns_results?.dmarc_record;
        if (dmarcRecord) {
            if (!dmarcRecord.record) {
                segments.push({ text: ". You " });
                segments.push({
                    text: "don't have",
                    highlight: { color: "danger", bold: true },
                    link: "#dns-dmarc"
                });
                segments.push({ text: " a DMARC record, " });
                segments.push({ text: "consider adding at least a record with the '", highlight: { bold : true } });
                segments.push({ text: "none", highlight: { monospace: true, bold: true } });
                segments.push({ text: "' policy", highlight: { bold : true } });
            } else if (!dmarcRecord.valid) {
                segments.push({ text: ". Your DMARC record has " });
                segments.push({
                    text: "issues",
                    highlight: { color: "danger", bold: true },
                    link: "#dns-dmarc"
                });
            } else if (dmarcRecord.policy === "none") {
                segments.push({ text: ". Your DMARC policy is " });
                segments.push({
                    text: "set to 'none'",
                    highlight: { color: "warning", bold: true },
                    link: "#dns-dmarc"
                });
                segments.push({ text: ", which provides monitoring but no protection" });
            } else if (dmarcRecord.policy === "quarantine" || dmarcRecord.policy === "reject") {
                segments.push({ text: ". Your DMARC policy is '" });
                segments.push({
                    text: dmarcRecord.policy,
                    highlight: { color: "good", bold: true, monospace: true },
                    link: "#dns-dmarc"
                });
                segments.push({ text: "'" });
                if (dmarcRecord.policy === "reject") {
                    segments.push({ text: ", which is great" });
                } else {
                    segments.push({ text: ", consider switching to '" });
                    segments.push({ text: "reject", highlight: { monospace: true, bold: true } });
                    segments.push({ text: "'" });
                }
            }
        } else if (dmarcResult && dmarcResult.result === "fail") {
            segments.push({ text: ". DMARC check " });
            segments.push({
                text: "failed",
                highlight: { color: "danger", bold: true },
                link: "#authentication-dmarc"
            });
        }

        // BIMI
        if (dmarcRecord.valid && dmarcRecord.policy != "none") {
            const bimiResult = report.authentication?.bimi;
            const bimiRecord = report.dns_results?.bimi_record;
            if (bimiRecord?.valid) {
                segments.push({ text: ". Your domain includes " });
                segments.push({
                    text: "BIMI",
                    highlight: { color: "good", bold: true },
                    link: "#dns-bimi"
                });
                segments.push({ text: " for brand indicator display" });
            } else if (bimiResult && bimiResult.details.indexOf("(No BIMI records found)") >= 0) {
                segments.push({ text: ". Your domain has no " });
                segments.push({
                    text: "BIMI record",
                    highlight: { color: "warning", bold: true },
                    link: "#dns-bimi"
                });
                segments.push({ text: ", you could " });
                segments.push({ text: "add a record to decline participation", highlight: { bold: true } });
            } else if (bimiResult || bimiRecord) {
                segments.push({ text: ". Your domain has " });
                segments.push({
                    text: "BIMI configured with issues",
                    highlight: { color: "warning", bold: true },
                    link: "#dns-bimi"
                });
            }
        }

        // ARC
        const arcResult = report.authentication?.arc;
        if (arcResult && arcResult.result !== "none") {
            segments.push({ text: ". " });
            segments.push({
                text: "ARC chain validation",
                link: "#authentication-arc"
            });
            segments.push({ text: " " });
            if (arcResult.chain_valid) {
                segments.push({
                    text: "passed",
                    highlight: { color: "good", bold: true }
                });
                segments.push({ text: ` with ${arcResult.chain_length} set${arcResult.chain_length !== 1 ? "s" : ""}, indicating proper email forwarding` });
            } else {
                segments.push({
                    text: "failed",
                    highlight: { color: "danger", bold: true }
                });
                segments.push({ text: ", which may indicate issues with email forwarding" });
            }
        }

        // Newsletter/marketing headers check
        const headers = report.header_analysis?.headers;
        const listUnsubscribe = headers?.["list-unsubscribe"];
        const listUnsubscribePost = headers?.["list-unsubscribe-post"];

        const hasNewsletterHeaders = (listUnsubscribe?.importance === "newsletter" && listUnsubscribe?.present) ||
                                      (listUnsubscribePost?.importance === "newsletter" && listUnsubscribePost?.present);

        if (!hasNewsletterHeaders && (listUnsubscribe?.importance === "newsletter" || listUnsubscribePost?.importance === "newsletter")) {
            segments.push({ text: ". This email is " });
            segments.push({
                text: "missing unsubscribe headers",
                highlight: { color: "warning", bold: true },
                link: "#header-details"
            });
            segments.push({ text: " and is " });
            segments.push({
                text: "not suitable for marketing campaigns",
                highlight: { bold: true }
            });
        }

        // Content/spam assessment
        const spamAssassin = report.spamassassin;
        const contentScore = report.summary?.content_score || 0;
        const spamScore = report.summary?.spam_score || 0;

        segments.push({ text: ". " });
        if (spamAssassin?.is_spam) {
            segments.push({ text: "Content is " });
            segments.push({
                text: "flagged as spam",
                highlight: { color: "danger", bold: true },
                link: "#spam-details"
            });
            segments.push({ text: " and needs review" });
        } else if (contentScore < 50) {
            segments.push({ text: "Content quality " });
            segments.push({
                text: "needs improvement",
                highlight: { color: "warning", bold: true },
                link: "#content-details"
            });
        } else if (contentScore >= 100 && spamScore >= 100) {
            segments.push({ text: "Content " });
            segments.push({
                text: "looks great",
                highlight: { color: "good", bold: true },
                link: "#content-details"
            });
        } else if (spamScore < 50) {
            segments.push({ text: "Your " });
            segments.push({
                text: "spam score",
                highlight: { color: "danger", bold: true },
                link: "#spam-details"
            });
            segments.push({ text: " is low" });
            if (report.spamassassin.tests.includes("EMPTY_MESSAGE")) {
                segments.push({ text: " (you sent an empty message, which can cause this issue, retry with some real content)", highlight: { bold: true } });
            }
        } else if (spamScore < 90) {
            segments.push({ text: "Pay attention to your " });
            segments.push({
                text: "spam score",
                highlight: { color: "warning", bold: true },
                link: "#spam-details"
            });
            if (report.spamassassin.tests.includes("EMPTY_MESSAGE")) {
                segments.push({ text: " (you sent an empty message, which can cause this issue, retry with some real content)", highlight: { bold: true } });
            }
        } else if (contentScore >= 80) {
            segments.push({ text: "Content " });
            segments.push({
                text: "looks good",
                highlight: { color: "good", bold: true },
                link: "#content-details"
            });
        } else {
            segments.push({ text: "Content " });
            segments.push({
                text: "should be reviewed",
                highlight: { color: "warning", bold: true },
                link: "#content-details"
            });
        }

        segments.push({ text: "." });

        return segments;
    }

    function getColorClass(color: "good" | "warning" | "danger"): string {
        switch (color) {
            case "good":
                return "text-success";
            case "warning":
                return "text-warning";
            case "danger":
                return "text-danger";
        }
    }

    const summarySegments = $derived(buildSummary());
</script>

<style>
    .summary-link {
        text-decoration: none;
        transition: opacity 0.2s ease;
    }

    .summary-link:hover {
        opacity: 0.8;
        text-decoration: underline;
    }

    .highlighted {
        font-weight: 600;
    }
</style>

<div class="card shadow-sm border-0 mb-4">
    <div class="card-body p-4">
        <h5 class="card-title mb-3">
            <i class="bi bi-card-text me-2"></i>
            Summary
        </h5>
        <p class="card-text text-muted mb-0" style="line-height: 1.8;">
            {#each summarySegments as segment}
                {#if segment.link}
                    <a
                        href={segment.link}
                        class="summary-link {segment.highlight ? getColorClass(segment.highlight.color) : ''} {segment.highlight?.bold ? 'highlighted' : ''} {segment.highlight?.emphasis ? 'fst-italic' : ''} {segment.highlight?.monospace ? 'font-monospace' : ''}"
                    >
                        {segment.text}
                    </a>
                {:else if segment.highlight}
                    <span class="{getColorClass(segment.highlight.color)} {segment.highlight.bold ? 'highlighted' : ''} {segment.highlight?.emphasis ? 'fst-italic' : ''} {segment.highlight?.monospace ? 'font-monospace' : ''}">
                        {segment.text}
                    </span>
                {:else}
                    {segment.text}
                {/if}
            {/each}
            Overall, your email received a grade <GradeDisplay grade={report.grade} score={report.score} size="inline" />{#if report.grade == "A" || report.grade == "A+"}, well done 🎉{:else if report.grade == "C" || report.grade == "D"}: you should try to increase your score to ensure inbox delivery.{:else if report.grade == "E"}: you could have delivery issues with common providers.{:else if report.grade == "F"}: it will most likely be rejected by most providers.{:else}!{/if} Check the details below 🔽
        </p>
    </div>
</div>
