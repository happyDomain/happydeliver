/**
 * Where to read up on what the report checks.
 *
 * A finding tells the reader what is wrong; the reference tells them why it matters to a
 * receiver and what the fix has to look like. The links go to the standard itself (an RFC, a
 * W3C recommendation) or to the policy of the receivers that enforce it, never to a vendor's
 * tutorial: those age, and they sell something.
 */
export interface DocLink {
    /** Short name a reader recognises: "RFC 7208", "WCAG 1.4.3". */
    label: string;
    /** What the reference is about, shown next to the label. */
    title?: string;
    url: string;
}

function rfc(number: number, title: string, section?: string): DocLink {
    return {
        label: section ? `RFC ${number} §${section}` : `RFC ${number}`,
        title,
        url: `https://www.rfc-editor.org/rfc/rfc${number}.html${section ? `#section-${section}` : ""}`,
    };
}

export const docs = {
    // Authentication
    spf: rfc(7208, "Sender Policy Framework"),
    spfAll: rfc(7208, 'SPF "all" mechanism', "5.1"),
    spfLookupLimit: rfc(7208, "SPF DNS lookup limits", "4.6.4"),
    spfHelo: rfc(7208, "Checking the HELO identity", "2.3"),
    dkim: rfc(6376, "DomainKeys Identified Mail"),
    dkimKeySize: rfc(8301, "DKIM cryptographic algorithm and key usage update", "3.2"),
    dmarc: rfc(9989, "Domain-based Message Authentication, Reporting, and Conformance (DMARC)"),
    dmarcAlignment: rfc(9989, "DMARC identifier alignment", "4.4"),
    dmarcPolicy: rfc(9989, "DMARC policy record", "4.7"),
    // RFC 9989 obsoletes it, but most guides and tools still cite it: the reader who knows
    // DMARC by this number finds it here.
    dmarcV1: rfc(7489, "DMARC v1, obsoleted by RFC 9989"),
    dmarcbis: {
        label: "RFC 9989 App. C.5",
        title: "Changes from DMARC v1 (pct=, rf=, ri= removed; t=, np=, psd= added)",
        url: "https://www.rfc-editor.org/rfc/rfc9989.html#appendix-C.5",
    },
    arc: rfc(8617, "Authenticated Received Chain"),
    authResults: rfc(8601, "Authentication-Results header field"),
    bimi: {
        label: "BIMI",
        title: "Brand Indicators for Message Identification",
        url: "https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/",
    },
    bimiGroup: {
        label: "BIMI Group",
        title: "Implementation guidance",
        url: "https://bimigroup.org/",
    },

    // Infrastructure
    reverseDns: rfc(1912, "Reverse DNS for every host", "2.1"),
    ehlo: rfc(5321, "EHLO must name the client's own host", "4.1.4"),
    mxLookup: rfc(5321, "Locating the target host (MX, implicit MX)", "5.1"),
    nullMx: rfc(7505, "Null MX: a domain that accepts no mail"),
    starttls: rfc(3207, "SMTP over TLS (STARTTLS)"),
    mtaSts: rfc(8461, "MTA Strict Transport Security"),
    dnsbl: rfc(5782, "DNS blacklists and whitelists"),

    // Message format
    messageFormat: rfc(5322, "Internet Message Format"),
    originDate: rfc(5322, "Origination date field (Date)", "3.6.1"),
    originator: rfc(5322, "Originator fields (From, Sender, Reply-To)", "3.6.2"),
    destination: rfc(5322, "Destination fields (To, Cc, Bcc)", "3.6.3"),
    messageId: rfc(5322, "Identification fields (Message-ID, In-Reply-To, References)", "3.6.4"),
    subject: rfc(5322, "Informational fields (Subject)", "3.6.5"),
    traceFields: rfc(5322, "Trace fields (Received, Return-Path)", "3.6.7"),
    mimeVersion: rfc(2045, "MIME-Version header field", "4"),
    multipartAlternative: rfc(2046, "multipart/alternative", "5.1.4"),
    listUnsubscribe: rfc(2369, "List-Unsubscribe and other list header fields"),
    oneClickUnsubscribe: rfc(8058, "One-click unsubscribe (List-Unsubscribe-Post)"),

    // Receivers' published requirements
    googleSenders: {
        label: "Gmail",
        title: "Email sender guidelines",
        url: "https://support.google.com/mail/answer/81126",
    },
    yahooSenders: {
        label: "Yahoo",
        title: "Sender best practices",
        url: "https://senders.yahooinc.com/best-practices/",
    },

    // Content
    wcagAltText: {
        label: "WCAG 1.1.1",
        title: "Non-text content",
        url: "https://www.w3.org/WAI/WCAG22/Understanding/non-text-content.html",
    },
    wcagContrast: {
        label: "WCAG 1.4.3",
        title: "Contrast (minimum)",
        url: "https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html",
    },
    wcagResize: {
        label: "WCAG 1.4.4",
        title: "Resize text",
        url: "https://www.w3.org/WAI/WCAG22/Understanding/resize-text.html",
    },
    canIEmail: {
        label: "Can I email",
        title: "HTML and CSS support across email clients",
        url: "https://www.caniemail.com/",
    },
    confusables: {
        label: "UTS #39",
        title: "Unicode security mechanisms (confusable characters)",
        url: "https://www.unicode.org/reports/tr39/",
    },
} satisfies Record<string, DocLink>;

/**
 * Where a header field is defined, for the header findings, which name the field but not the
 * text that governs it. A field missing from this table gets no link rather than a guess.
 */
const headerDocs: Record<string, DocLink[]> = {
    date: [docs.originDate],
    from: [docs.originator],
    sender: [docs.originator],
    "reply-to": [docs.originator],
    to: [docs.destination],
    cc: [docs.destination],
    "message-id": [docs.messageId],
    "in-reply-to": [docs.messageId],
    references: [docs.messageId],
    subject: [docs.subject],
    received: [docs.traceFields],
    "return-path": [docs.traceFields],
    "mime-version": [docs.mimeVersion],
    "list-unsubscribe": [docs.listUnsubscribe, docs.oneClickUnsubscribe],
    "list-unsubscribe-post": [docs.oneClickUnsubscribe],
    "authentication-results": [docs.authResults],
    "dkim-signature": [docs.dkim],
    "arc-seal": [docs.arc],
};

export function headerDocLinks(header: string): DocLink[] {
    return headerDocs[header.toLowerCase()] ?? [];
}

/**
 * References for a content or attachment issue type. Types whose fix is a matter of judgement
 * (an image-heavy message, a suspicious link) get none: there is no standard to point at, and
 * the advice the analysis wrote is the better guide.
 */
const issueDocs: Partial<Record<string, DocLink[]>> = {
    missing_alt: [docs.wcagAltText],
    low_contrast: [docs.wcagContrast],
    text_html_mismatch: [docs.multipartAlternative],
    missing_plaintext: [docs.multipartAlternative],
    client_compat: [docs.canIEmail],
    broken_html: [docs.canIEmail],
    homograph_url: [docs.confusables],
    invalid_message_id: [docs.messageId],
    reply_without_references: [docs.messageId],
    domain_misaligned: [docs.dmarcAlignment],
    domain_relaxed_aligned: [docs.dmarcAlignment],
    return_path_misaligned: [docs.dmarcAlignment],
    dkim_misaligned: [docs.dmarcAlignment],
    spf_missing: [docs.spf, docs.googleSenders],
    spf_invalid: [docs.spf],
    spf_include_invalid: [docs.spf, docs.spfLookupLimit],
    spf_too_many_lookups: [docs.spfLookupLimit],
    spf_all_pass: [docs.spfAll],
    spf_all_neutral: [docs.spfAll],
    spf_all_missing: [docs.spfAll],
    spf_all_softfail: [docs.spfAll],
    dkim_missing: [docs.dkim, docs.googleSenders],
    dkim_invalid: [docs.dkim],
    dkim_sha1: [docs.dkimKeySize],
    dkim_key_short: [docs.dkimKeySize],
    dkim_key_weak: [docs.dkimKeySize],
    mx_missing: [docs.mxLookup],
    mx_invalid: [docs.mxLookup],
    domain_unreachable: [docs.mxLookup],
    helo_spf_missing: [docs.spfHelo],
    helo_spf_invalid: [docs.spfHelo],
    dmarc_missing: [docs.dmarc, docs.googleSenders, docs.yahooSenders],
    dmarc_invalid: [docs.dmarcPolicy],
    dmarc_policy_none: [docs.dmarcPolicy, docs.yahooSenders],
    dmarc_policy_quarantine: [docs.dmarcPolicy],
    dmarc_test_mode: [docs.dmarcbis],
    dmarc_pct: [docs.dmarcbis],
    dmarc_pct_deprecated: [docs.dmarcbis],
    dmarc_sp_weaker: [docs.dmarcPolicy],
    dmarc_np_weaker: [docs.dmarcbis],
    dmarc_deprecated_tags: [docs.dmarcbis],
    ptr_missing: [docs.reverseDns, docs.googleSenders],
    ptr_multiple: [docs.reverseDns],
    fcrdns_mismatch: [docs.reverseDns, docs.googleSenders],
    helo_ptr_mismatch: [docs.ehlo],
    auth_unavailable: [docs.authResults],
    auth_unevaluated: [docs.authResults],
    spf_fail: [docs.spf, docs.googleSenders],
    spf_softfail: [docs.spf, docs.googleSenders],
    spf_neutral: [docs.spf],
    spf_permerror: [docs.spfLookupLimit, docs.spf],
    spf_temperror: [docs.spf],
    spf_helo_fail: [docs.spfHelo],
    dkim_fail: [docs.dkim],
    dkim_temperror: [docs.dkim],
    dkim_extra_fail: [docs.dkim],
    dmarc_fail: [docs.dmarcAlignment, docs.dmarc],
    dmarc_permerror: [docs.dmarcPolicy],
    dmarc_temperror: [docs.dmarcPolicy],
    iprev_fail: [docs.reverseDns, docs.googleSenders],
    iprev_error: [docs.reverseDns],
    tls_missing: [docs.starttls, docs.googleSenders],
    x_aligned_from_fail: [docs.dmarcAlignment],
    x_google_dkim_fail: [docs.dkim],
    arc_fail: [docs.arc],
    bimi_declined: [docs.bimi, docs.bimiGroup],
    bimi_not_honored: [docs.bimi, docs.bimiGroup],
    bimi_missing: [docs.bimi, docs.bimiGroup],
    bimi_dmarc_not_enforced: [docs.bimi, docs.dmarcPolicy],
    bimi_invalid: [docs.bimi, docs.bimiGroup],
    bimi_unverified: [docs.bimi, docs.bimiGroup],
    bimi_vmc_missing: [docs.bimi, docs.bimiGroup],
    bimi_check_warning: [docs.bimi, docs.bimiGroup],
    rbl_listed: [docs.dnsbl],
};

export function issueDocLinks(type: string): DocLink[] {
    return issueDocs[type] ?? [];
}

/**
 * Where to look up, and ask for the removal of, a listing on the DNS blacklists this instance
 * queries by default. A list missing here (SORBS, whose site is gone, or one an instance adds)
 * still gets the generic advice; only the link is left out, rather than pointed at a page that
 * may not exist.
 */
const rblLookups: Record<string, DocLink> = {
    "zen.spamhaus.org": { label: "Spamhaus", url: "https://check.spamhaus.org/" },
    "cbl.abuseat.org": { label: "Spamhaus (CBL)", url: "https://check.spamhaus.org/" },
    "bl.spamcop.net": { label: "SpamCop", url: "https://www.spamcop.net/bl.shtml" },
    "b.barracudacentral.org": {
        label: "Barracuda",
        url: "https://www.barracudacentral.org/lookups",
    },
    "dnsbl-1.uceprotect.net": {
        label: "UCEPROTECT",
        url: "https://www.uceprotect.net/en/rblcheck.php",
    },
    "dnsbl-2.uceprotect.net": {
        label: "UCEPROTECT",
        url: "https://www.uceprotect.net/en/rblcheck.php",
    },
    "dnsbl-3.uceprotect.net": {
        label: "UCEPROTECT",
        url: "https://www.uceprotect.net/en/rblcheck.php",
    },
    "psbl.surriel.com": { label: "PSBL", url: "https://psbl.org/" },
    "dnsbl.dronebl.org": { label: "DroneBL", url: "https://dronebl.org/lookup" },
    "bl.mailspike.net": { label: "Mailspike", url: "https://mailspike.io/ip_verify" },
    "z.mailspike.net": { label: "Mailspike", url: "https://mailspike.io/ip_verify" },
    "bl.rbl-dns.com": { label: "RBL-DNS", url: "https://www.rbl-dns.com/bl" },
    "bl.nszones.com": { label: "NSZones", url: "https://www.nszones.com/bl" },
};

export function rblLookupLink(rbl: string): DocLink | undefined {
    const link = rblLookups[rbl.toLowerCase()];
    return link ? { ...link, title: `Look up and request removal from ${rbl}` } : undefined;
}

/**
 * The spam filters' own sites. Not standards, but there is no other reference for what a
 * filter does: each documents its rules and how it adds them up.
 */
export const spamFilterSites = {
    spamassassin: { label: "spamassassin.apache.org", url: "https://spamassassin.apache.org/" },
    rspamd: { label: "rspamd.com", url: "https://rspamd.com/" },
} satisfies Record<string, DocLink>;
