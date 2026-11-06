import type { Report } from "#lib/api/types.gen.js";

const HOUR = 3600 * 1000;

/** How much an age should worry the reader, null when it should not at all. */
export function ageLevel(ms: number): "info" | "warning" | null {
    if (ms > 24 * HOUR) return "warning";
    if (ms > 6 * HOUR) return "info";
    return null;
}

/**
 * How long after the message was last received the report was generated, in milliseconds.
 * The authentication results date from that reception, while the DNS records, the blacklists
 * and the logo are read when the report is generated: an uploaded file, or a report generated
 * anew, can put hours between them. Null when the chain gives no date to go by, and for a date
 * in the future, which says more of the clock of the server than of the message.
 */
export function analysisLag(report: Report): number | null {
    const received = report.header_analysis?.received_chain?.[0]?.timestamp;
    if (!received) return null;

    const lag = new Date(report.created_at).getTime() - new Date(received).getTime();
    return lag >= 0 ? lag : null;
}

/** A length of time in the largest unit that fits, for a sentence: "3 hours", "2 days". */
export function formatDuration(ms: number): string {
    const hours = Math.round(ms / HOUR);
    if (hours < 24) return hours === 1 ? "1 hour" : `${hours} hours`;
    const days = Math.round(hours / 24);
    return days === 1 ? "1 day" : `${days} days`;
}
