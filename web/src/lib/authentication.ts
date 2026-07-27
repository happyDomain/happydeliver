import type { AuthenticationResults } from "$lib/api/types.gen";

/**
 * True when none of the required authentication mechanisms were reported.
 *
 * This is not a sender problem: it means the receiving mail server did not
 * produce a usable `Authentication-Results` header (not configured to verify
 * authentication, or the header's authserv-id does not match the configured
 * `--receiver-hostname`). Grades derived from these results are meaningless in
 * that case.
 */
export function hasNoAuthenticationResults(authentication?: AuthenticationResults): boolean {
    if (!authentication) return true;

    return (
        !authentication.spf &&
        (!authentication.dkim || authentication.dkim.length === 0) &&
        !authentication.dmarc
    );
}
