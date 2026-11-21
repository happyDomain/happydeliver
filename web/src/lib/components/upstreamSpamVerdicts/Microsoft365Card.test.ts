import { describe, expect, it } from "vitest";

import { upstreamSpamVerdictCards } from "./index.js";
import Microsoft365Card from "./Microsoft365Card.svelte";

describe("upstreamSpamVerdictCards", () => {
    it("shows Microsoft 365's verdict with its own card", () => {
        expect(upstreamSpamVerdictCards.microsoft365).toBe(Microsoft365Card);
    });
});
