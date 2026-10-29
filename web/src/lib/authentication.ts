import type { AuthenticationResults, Report } from "#lib/api/types.gen.js";
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
