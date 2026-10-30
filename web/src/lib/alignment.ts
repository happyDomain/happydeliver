import type { DmarcRecord, DomainAlignment } from "#lib/api/types.gen.js";

/** How closely the domains authenticating a message align with its From domain. */
export type AlignmentLevel = "exact" | "organizational" | "none";

/**
 * How closely the domains authenticating the message align with the From domain, counting
 * only what DMARC would: a domain that shares only the organizational domain does not align
 * in strict mode, which the policy sets apart for the Return-Path (aspf=s) and the DKIM
 * signatures (adkim=s). Without a usable record, DMARC aligns in relaxed mode.
 *
 * It mirrors how the header score weighs the alignment.
 */
export function dmarcAlignment(
    alignment: DomainAlignment | undefined,
    dmarc: DmarcRecord | undefined,
): AlignmentLevel {
    if (!alignment) return "none";

    const spfStrict = !!dmarc?.valid && dmarc.spf_alignment === "strict";
    const dkimStrict = !!dmarc?.valid && dmarc.dkim_alignment === "strict";
    const from = alignment.from_domain?.toLowerCase() ?? "";
    const fromOrg = alignment.from_org_domain?.toLowerCase() ?? "";

    const levelOf = (domain: string, orgDomain: string | undefined, strict: boolean) => {
        if (domain.toLowerCase() === from) return 2;
        if (!strict && orgDomain && orgDomain.toLowerCase() === fromOrg) return 1;
        return 0;
    };

    const levels: number[] = [];
    if (from && alignment.return_path_domain) {
        levels.push(
            levelOf(alignment.return_path_domain, alignment.return_path_org_domain, spfStrict),
        );
    }
    if (from) {
        for (const d of alignment.dkim_domains ?? []) {
            levels.push(levelOf(d.domain, d.org_domain, dkimStrict));
        }
    }

    // Nothing to compare: no Return-Path nor DKIM signature to hold against the From domain
    if (levels.length === 0) {
        if (alignment.aligned) return "exact";
        return alignment.relaxed_aligned ? "organizational" : "none";
    }

    return (["none", "organizational", "exact"] as const)[Math.max(...levels)];
}
