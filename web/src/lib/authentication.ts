import type { AuthenticationResults, Report } from "$lib/api/types.gen";

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
 */
export function hasNoAuthenticationResults(authentication?: AuthenticationResults): boolean {
    if (!authentication) return true;

    return (
        !authentication.spf &&
        (!authentication.dkim || authentication.dkim.length === 0) &&
        !authentication.dmarc
    );
}

/**
 * True when some, but not all, of the required authentication mechanisms were reported.
 *
 * The verdicts that are present were produced by whichever infrastructure received the
 * message before it reached happyDeliver (the sender's own instance, or the server that
 * received an uploaded file) — happyDeliver does not recompute them. The missing ones show up
 * as "Not tested" and can only be filled in by sending a test message directly to happyDeliver.
 */
export function hasPartialAuthenticationResults(authentication?: AuthenticationResults): boolean {
    if (!authentication) return false;
    if (hasNoAuthenticationResults(authentication)) return false;

    return (
        !authentication.spf ||
        !authentication.dkim ||
        authentication.dkim.length === 0 ||
        !authentication.dmarc
    );
}
