import type { Component } from "svelte";

import type { UpstreamSpamVerdict } from "#lib/api/types.gen.js";

/** What a card showing an upstream verdict is given. */
export interface UpstreamSpamVerdictCardProps {
    verdict: UpstreamSpamVerdict;
}

/**
 * A card of this directory: its component, and the filter it shows, exported from its
 * module script as `filter`, the key the backend reports the verdict under.
 */
interface UpstreamSpamVerdictCardModule {
    filter: string;
    default: Component<UpstreamSpamVerdictCardProps>;
}

const modules = import.meta.glob<UpstreamSpamVerdictCardModule>("./*.svelte", { eager: true });

/**
 * The card showing each upstream filter's verdict, keyed by filter. Showing a new filter
 * is adding its card to this directory: nothing to register by hand. A filter without a card
 * gets the generic one.
 */
export const upstreamSpamVerdictCards: Record<
    string,
    Component<UpstreamSpamVerdictCardProps>
> = Object.fromEntries(Object.values(modules).map((card) => [card.filter, card.default]));
