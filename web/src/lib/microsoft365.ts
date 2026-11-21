import type { DocLink } from "#lib/docs.js";

/**
 * What Microsoft 365 stamped on the message, as the backend reports it in the details of its
 * upstream spam verdict.
 */
export interface Microsoft365Details {
    /** Whether Microsoft filtered the message leaving a tenant, entering one or within one. */
    direction?: "outbound" | "inbound" | "internal";
    /**
     * Spam confidence level, -1 or 0 to 9. Microsoft states it no longer decides the verdict
     * in its cloud: the category does.
     */
    scl?: number;
    /** Bulk complaint level: the higher, the more recipients complain about the sender. */
    bcl?: number;
    /** Whether spam filtering identified the message as bulk (SRV:BULK). */
    bulk?: boolean;
    /** Spam filtering verdict (SFV). */
    filter_verdict?: string;
    /** Threat policy applied (CAT). */
    category?: string;
    /** The raw X-Forefront-Antispam-Report header. */
    report?: string;
}

/** Microsoft's own documentation of these headers. */
export const m365Site: DocLink = {
    label: "Microsoft's anti-spam message headers",
    url: "https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo",
};

/** What Microsoft's filtering verdicts (SFV) stand for. */
export const m365FilterVerdicts: Record<string, string> = {
    NSPM: "not spam",
    SPM: "spam",
    SKN: "spam filtering bypassed by a mail flow rule",
    SKA: "sender on an anti-spam policy's allow list, filtering skipped",
    SKB: "sender on an anti-spam policy's block list",
    SKS: "marked spam by a mail flow rule before filtering",
    SKI: "source IP address on the IP Allow List, filtering skipped",
    SKQ: "released from quarantine",
    SFE: "sender on the recipient's safe senders list",
    BLK: "sender on the recipient's blocked senders list",
};

/** What Microsoft's threat policies (CAT) stand for. */
export const m365Categories: Record<string, string> = {
    NONE: "nothing found",
    AMP: "malware",
    MALW: "malware",
    SAP: "malware, found by Safe Attachments",
    FTBP: "blocked file type",
    HPHSH: "high confidence phishing",
    HPHISH: "high confidence phishing",
    PHSH: "phishing",
    INTOS: "intra-organization phishing",
    SPOOF: "spoofing",
    UIMP: "user impersonation",
    DIMP: "domain impersonation",
    GIMP: "mailbox intelligence impersonation",
    BIMP: "brand impersonation",
    HSPM: "high confidence spam",
    SPM: "spam",
    OSPM: "outbound spam",
    BULK: "bulk",
};

/** The filtering verdicts (SFV) by which Microsoft treated the message as spam. */
const spamVerdicts = new Set(["SPM", "SKS", "SKB", "BLK"]);

/** What a bulk complaint level (BCL) means, against Microsoft's policies. */
export function m365BclMeaning(bcl: number): string {
    if (bcl >= 7) return "bulk under every policy";
    if (bcl === 6) return "bulk under the Standard and Strict preset policies";
    if (bcl === 5) return "bulk under the Strict preset policy";
    if (bcl >= 1) return "from a bulk sender, below the thresholds";
    return "not from a bulk sender";
}

/**
 * What the Standard and Strict preset policies make of the message, where they go further
 * than the default ones the verdict follows. Undefined when they change nothing.
 */
export function m365UnderPresets(details: Microsoft365Details): string | undefined {
    if (details.direction === "outbound") return undefined;

    const category = details.category ?? "";
    switch (category) {
        case "PHSH":
        case "HSPM":
            return "quarantined under the Standard and Strict preset policies";
        case "UIMP":
        case "DIMP":
            return "no action under the default policy, quarantined under the Standard and Strict preset policies";
        case "GIMP":
            return "no action under the default policy, junk folder under the Standard preset policy, quarantined under the Strict one";
        case "SPOOF":
            return "quarantined under the Strict preset policy, and under every policy when it fails a DMARC policy of quarantine; rejected when it fails one of reject";
        case "SPM":
        case "BULK":
            return "quarantined under the Strict preset policy";
    }

    if (spamVerdicts.has(details.filter_verdict ?? "") || details.bulk) {
        return "quarantined under the Strict preset policy";
    }

    const bcl = details.bcl ?? 0;
    if (bcl >= 7) return "quarantined under the Strict preset policy";
    if (bcl === 6)
        return "junk folder under the Standard preset policy, quarantined under the Strict one";
    if (bcl === 5) return "quarantined under the Strict preset policy";

    return undefined;
}
