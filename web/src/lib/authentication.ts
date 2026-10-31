import type {
    AuthenticationResults,
    AuthResult,
    DmarcRecord,
    DomainAlignment,
    Report,
} from "#lib/api/types.gen.js";
import type { CheckStatus } from "#lib/components/CheckCard.svelte";

/**
 * Where the analyzed message comes from.
 *
 * Reports generated before this field existed carry no source; they were all received by
 * this instance's MTA.
 */
export type MessageSource = NonNullable<Report["source"]>;

/**
 * True when the report describes a file the user supplied rather than a message delivered to
 * this instance.
 *
 * It changes who is responsible for a missing authentication verdict: for an uploaded file
 * the verdicts come from whichever server originally received the message, so their absence
 * says nothing about this instance's configuration.
 */
export function isUploadedMessage(source?: MessageSource): boolean {
    return source === "uploaded";
}

/**
 * Short explanation of why no authentication grade can be shown, suitable for a tooltip.
 */
export function noAuthResultsTitle(source?: MessageSource): string {
    if (isUploadedMessage(source)) {
        return "The uploaded file carries no usable authentication result, so no grade can be computed. This depends on the server that originally received the message, not on this instance.";
    }

    return "This server did not report any authentication result, so no grade can be computed. Contact the administrator of this instance.";
}

/**
 * True when none of the required authentication mechanisms were reported.
 *
 * This is not a sender problem: it means no usable `Authentication-Results` header was
 * available. For a message received by this instance that points at its configuration (the
 * receiving mail server does not verify authentication, or the header's authserv-id does not
 * match the configured `--receiver-hostname`); for an uploaded file it simply means the
 * message did not carry one. Grades derived from these results are meaningless either way.
 *
 * An SPF verdict on the HELO identity alone counts: the receiver did evaluate the message, it
 * just says nothing about the envelope sender. The backend scores it accordingly, so hiding
 * the grade here would contradict it.
 */
export function hasNoAuthenticationResults(authentication?: AuthenticationResults): boolean {
    if (!authentication) return true;

    return reportedMechanisms(authentication).every((reported) => !reported);
}

/** Whether each of the required authentication mechanisms was reported, in a fixed order. */
function reportedMechanisms(authentication: AuthenticationResults): boolean[] {
    return [
        !!authentication.spf || !!authentication.spf_helo,
        !!authentication.dkim?.length,
        !!authentication.dmarc,
    ];
}

/** A verdict as the receiver wrote it (the resinfo of RFC 8601), split into its parts. */
export interface ReportedVerdict {
    /** What the receiver wrote in parentheses: its own explanation of the verdict. */
    comments: string[];
    /** The properties it reported, by their lowercased name: smtp.mailfrom, header.d… */
    properties: Record<string, string>;
}

/**
 * Splits the details of a verdict into the comments and the properties the receiver wrote.
 *
 * The details start with the result itself, which carries no "=" and is left out. Values may
 * be quoted, and comments may nest, as RFC 5322 allows.
 */
export function parseVerdictDetails(details?: string): ReportedVerdict {
    const parsed: ReportedVerdict = { comments: [], properties: {} };
    if (!details) return parsed;

    let i = 0;
    while (i < details.length) {
        const c = details[i];
        if (/[\s;]/.test(c)) {
            i++;
        } else if (c === "(") {
            let depth = 0;
            let comment = "";
            for (; i < details.length; i++) {
                const d = details[i];
                if (d === "\\" && i + 1 < details.length) {
                    comment += details[++i];
                    continue;
                }
                if (d === "(" && depth++ === 0) continue;
                if (d === ")" && --depth === 0) break;
                comment += d;
            }
            i++;
            if (comment.trim()) parsed.comments.push(comment.trim());
        } else {
            let token = "";
            let quoted = false;
            for (; i < details.length; i++) {
                const d = details[i];
                if (d === '"') quoted = !quoted;
                else if (!quoted && /[\s;(]/.test(d)) break;
                token += d;
            }
            const eq = token.indexOf("=");
            if (eq > 0) {
                const value = token.slice(eq + 1).replace(/^"(.*)"$/, "$1");
                parsed.properties[token.slice(0, eq).toLowerCase()] = value;
            }
        }
    }

    return parsed;
}

/**
 * The verdict as it reads in the Authentication-Results header: the details the analyser
 * kept, after the name of the method they are about. Details that do not start with the
 * result, as receivers write it in that header, were not taken from it (a legacy Received-SPF
 * one capitalizes it), and are left as they are.
 */
export function rawVerdict(method: string, result: string, details?: string): string | undefined {
    if (!details) return undefined;
    const startsWithResult = details.split(/[\s;(]/, 1)[0] === result;
    return startsWithResult ? `${method}=${details}` : details;
}

const normalizeDomain = (domain: string) => domain.trim().replace(/\.$/, "").toLowerCase();

/** Whether two domains are the same, whatever their case and a trailing dot. */
export function sameDomain(a: string | undefined, b: string | undefined): boolean {
    return !!a && !!b && normalizeDomain(a) === normalizeDomain(b);
}

/**
 * Whether an authenticated domain is aligned with the From domain, as DMARC compares them:
 * the same domain in strict mode, the same organizational domain in relaxed mode. Undefined
 * when the organizational domains this takes are unknown.
 */
export function isAlignedWith(
    domain: string | undefined,
    orgDomain: string | undefined,
    fromDomain: string | undefined,
    fromOrgDomain: string | undefined,
    mode: "relaxed" | "strict" = "relaxed",
): boolean | undefined {
    if (!domain || !fromDomain) return undefined;
    if (sameDomain(domain, fromDomain)) return true;
    if (mode === "strict") return false;
    if (!orgDomain || !fromOrgDomain) return undefined;
    return sameDomain(orgDomain, fromOrgDomain);
}

/** The mechanisms whose verdicts the report explains. */
export type VerdictMechanism =
    | "spf"
    | "spf_helo"
    | "dkim"
    | "dmarc"
    | "iprev"
    | "x_ptr"
    | "x_tls"
    | "x_aligned_from"
    | "bimi"
    | "arc";

// What each verdict means, worded after the RFC defining it (7208 for SPF, 8601 for DKIM,
// DMARC and iprev, 8617 for ARC) or, for the others, after what the receiver compares.
const verdictMeanings: Record<VerdictMechanism, Record<string, string>> = {
    spf: {
        pass: "The SPF record of the domain allows the sending IP.",
        fail: "The SPF record of the domain explicitly forbids the sending IP (-all).",
        softfail:
            "The SPF record of the domain does not list the sending IP, and asks receivers to treat the message with suspicion (~all) rather than reject it.",
        neutral: "The SPF record of the domain says nothing about the sending IP (?all).",
        none: "The domain publishes no SPF record, or there was no domain to check.",
        temperror: "A temporary DNS error prevented the check; it may pass on a later delivery.",
        permerror:
            "The SPF record could not be evaluated: it is malformed, or takes more than 10 DNS lookups.",
    },
    spf_helo: {},
    dkim: {
        pass: "The signature verifies with the public key the signing domain publishes.",
        fail: "The signature does not verify: the message was changed after it was signed, or the key does not match.",
        neutral: "The signature could not be processed, for instance because of a syntax error.",
        none: "The message is not signed.",
        temperror: "The public key could not be fetched because of a temporary DNS error.",
        permerror:
            "The signature cannot be verified: the public key is missing or invalid, or the signature is malformed.",
    },
    dmarc: {
        pass: "SPF or DKIM passed for a domain aligned with the From address.",
        fail: "Neither SPF nor DKIM passed for a domain aligned with the From address: the receiver applies the policy of the domain.",
        none: "The From domain publishes no DMARC record.",
        temperror: "The DMARC record could not be fetched because of a temporary DNS error.",
        permerror: "The DMARC record of the From domain could not be interpreted.",
    },
    iprev: {
        pass: "The sending IP has a name in reverse DNS, and that name resolves back to it.",
        fail: "The name the reverse DNS gives for the sending IP does not resolve back to it.",
        temperror: "A temporary DNS error prevented the check.",
        permerror: "The sending IP has no name in reverse DNS.",
    },
    x_ptr: {
        pass: "The hostname the server announced is the name its IP has in reverse DNS.",
        fail: "The hostname the server announced differs from the name its IP has in reverse DNS.",
        none: "There was no reverse DNS name to compare the announced hostname with.",
        temperror: "A temporary DNS error prevented the comparison.",
        permerror: "The comparison could not be made.",
    },
    x_tls: {
        pass: "The message travelled over an encrypted connection.",
        none: "The message travelled over a plain, unencrypted connection.",
        fail: "The message travelled over a plain, unencrypted connection.",
    },
    x_aligned_from: {
        pass: "The envelope sender and the From address are in the same domain.",
        domain_pass: "The envelope sender and the From address are in the same domain.",
        orgdomain_pass:
            "The envelope sender and the From address share the same organizational domain.",
        fail: "The envelope sender and the From address are in different domains.",
    },
    bimi: {
        pass: "The record and the logo are valid: the receiver may show the logo.",
        none: "The From domain publishes no BIMI record.",
        fail: "The BIMI record or the logo it points to is not valid.",
        declined: "The domain publishes a BIMI record that declines to show a logo.",
        skipped:
            "BIMI was not evaluated, usually because the DMARC policy of the domain is not at enforcement.",
        temperror: "A temporary error prevented fetching the record or the logo.",
        permerror: "The BIMI record could not be interpreted.",
    },
    arc: {
        pass: "Every seal of the chain verifies: the intermediaries vouch for the results they saw.",
        fail: "A seal of the chain does not verify: the message was changed after it was sealed.",
        none: "No intermediary sealed the message.",
    },
};
// SPF means the same, whichever identity it checks.
verdictMeanings.spf_helo = {
    ...verdictMeanings.spf,
    pass: "The SPF record of the announced hostname allows the sending IP.",
    none: "The announced hostname publishes no SPF record.",
};

/** What a verdict means, in plain words, or undefined for one the report cannot explain. */
export function verdictMeaning(mechanism: VerdictMechanism, result?: string): string | undefined {
    return result ? verdictMeanings[mechanism][result] : undefined;
}

/** How a verdict reads, for a mechanism the score requires or one that is optional. */
export function verdictStatus(result: string | undefined, required: boolean): CheckStatus {
    switch (result) {
        case "pass":
        case "domain_pass":
        case "orgdomain_pass":
            return "pass";
        case "fail":
        case "permerror":
        case "invalid":
            return "fail";
        case "softfail":
        case "neutral":
        case "temperror":
            return "warn";
        case "declined":
        case "skipped":
            return "info";
        case undefined:
        case "none":
        case "missing":
            return required ? "fail" : "neutral";
        default:
            return "neutral";
    }
}

/** How a domain relates to the From domain, which is all DMARC alignment asks. */
export type DomainRelation = "same" | "organizational" | "unrelated";

/**
 * One identity DMARC may rest on, held against the From domain: the Return-Path, which SPF
 * authenticates, or the domain a DKIM signature is made for.
 */
export interface AlignmentIdentity {
    mechanism: "SPF" | "DKIM";
    /** The DMARC tag setting how closely this identity has to match. */
    tag: "aspf" | "adkim";
    mode?: "relaxed" | "strict";
    domain: string;
    orgDomain?: string;
    /** The Return-Path address, for SPF. */
    address?: string;
    /** The selector of the signature, for DKIM. */
    selector?: string;
    relation: DomainRelation;
    /** Aligned under the mode of the policy: strict alignment wants the same domain. */
    aligned: boolean;
    /** The verdict of its mechanism, when the receiver reported one for this domain. */
    verdict?: AuthResult;
    /** Aligned and passing: this identity alone is enough for DMARC. */
    counts: boolean;
}

/** The identities DMARC may rest on, each with the verdict of its mechanism. */
export function alignmentIdentities(
    alignment: DomainAlignment | undefined,
    authentication: AuthenticationResults | undefined,
    dmarcRecord: DmarcRecord | undefined,
): AlignmentIdentity[] {
    if (!alignment) return [];

    const identity = (
        found: Pick<AlignmentIdentity, "mechanism" | "tag" | "mode" | "domain" | "orgDomain">,
        verdict: AuthResult | undefined,
    ) => {
        const relation: DomainRelation = sameDomain(found.domain, alignment.from_domain)
            ? "same"
            : sameDomain(found.orgDomain, alignment.from_org_domain)
              ? "organizational"
              : "unrelated";
        const aligned =
            isAlignedWith(
                found.domain,
                found.orgDomain,
                alignment.from_domain,
                alignment.from_org_domain,
                found.mode,
            ) ?? false;
        return {
            ...found,
            relation,
            aligned,
            verdict,
            counts: aligned && verdict?.result === "pass",
        };
    };

    const identities: AlignmentIdentity[] = [];
    if (alignment.return_path_domain) {
        const spf = authentication?.spf;
        identities.push({
            ...identity(
                {
                    mechanism: "SPF",
                    tag: "aspf",
                    mode: dmarcRecord?.spf_alignment,
                    domain: alignment.return_path_domain,
                    orgDomain: alignment.return_path_org_domain,
                },
                // The envelope sender SPF checked is the Return-Path, unless the receiver
                // names another one
                spf && (!spf.domain || sameDomain(spf.domain, alignment.return_path_domain))
                    ? spf
                    : undefined,
            ),
            address: alignment.return_path,
        });
    }

    // The analysis lists the domains of the signatures in the order the receiver reported
    // them, leaving out those it named no domain for, so both lists match one for one:
    // matching by domain is only a safeguard, should they ever differ.
    const signatures = (authentication?.dkim ?? []).filter((d) => d.domain);
    const zipped = signatures.length === alignment.dkim_domains?.length;
    (alignment.dkim_domains ?? []).forEach((dkim, i) => {
        const signature = zipped
            ? signatures[i]
            : signatures.find((d) => sameDomain(d.domain, dkim.domain));
        identities.push({
            ...identity(
                {
                    mechanism: "DKIM",
                    tag: "adkim",
                    mode: dmarcRecord?.dkim_alignment,
                    domain: dkim.domain,
                    orgDomain: dkim.org_domain,
                },
                signature,
            ),
            selector: signature?.selector,
        });
    });

    return identities;
}
