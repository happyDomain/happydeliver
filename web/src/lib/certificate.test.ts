import { describe, expect, it } from "vitest";

import { displayName, inReadingOrder, parseDistinguishedName } from "#lib/certificate.js";

describe("parseDistinguishedName", () => {
    it("unescapes the separators a value contains", () => {
        expect(
            parseDistinguishedName(
                "CN=DigiCert Verified Mark RSA4096 SHA256 2021 CA1,O=DigiCert\\, Inc.,C=US",
            ),
        ).toEqual([
            {
                type: "CN",
                label: "Common name",
                value: "DigiCert Verified Mark RSA4096 SHA256 2021 CA1",
            },
            { type: "O", label: "Organization", value: "DigiCert, Inc." },
            { type: "C", label: "Country", value: "US" },
        ]);
    });

    it("decodes the strings an attribute known by OID is given as", () => {
        // UTF8String "Registered Mark", PrintableString "US"
        expect(
            parseDistinguishedName(
                "1.3.6.1.4.1.53087.1.13=#0c0f52656769737465726564204d61726b+1.3.6.1.4.1.53087.1.3=#13025553",
            ),
        ).toEqual([
            { type: "1.3.6.1.4.1.53087.1.13", label: "Mark type", value: "Registered Mark" },
            { type: "1.3.6.1.4.1.53087.1.3", label: "Trademark country", value: "US" },
        ]);
    });

    it("keeps a value it cannot decode as it was written", () => {
        expect(parseDistinguishedName("1.2.3.4=#0201ff")).toEqual([
            { type: "1.2.3.4", label: "1.2.3.4", value: "#0201ff" },
        ]);
    });
});

describe("displayName", () => {
    it("prefers the organization to the common name", () => {
        expect(displayName(parseDistinguishedName("CN=Example Logo,O=Example Corp"))).toBe(
            "Example Corp",
        );
        expect(displayName(parseDistinguishedName("CN=Example Logo"))).toBe("Example Logo");
        expect(displayName([])).toBeUndefined();
    });
});

describe("inReadingOrder", () => {
    it("puts the holder first and the attributes it does not know last", () => {
        const dn = "1.2.3.4=x,C=US,1.3.6.1.4.1.53087.1.13=#0c014d,O=Example Corp,CN=Example";
        expect(inReadingOrder(parseDistinguishedName(dn)).map((a) => a.type)).toEqual([
            "O",
            "CN",
            "1.3.6.1.4.1.53087.1.13",
            "C",
            "1.2.3.4",
        ]);
    });
});
