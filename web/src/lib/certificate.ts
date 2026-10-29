/** One attribute of a distinguished name, as a reader would name it. */
export interface NameAttribute {
    /** The attribute type as the name spells it: a short name (CN, O…) or a dotted OID. */
    type: string;
    /** What the type means, or the type itself when it is not a known one. */
    label: string;
    value: string;
}

// The short names Go's pkix.Name.String() spells out, and the attributes a mark
// certificate adds, which it only gives by OID; in the order a reader looks for them:
// who the holder is, the mark registered, the legal entity, then its address.
const known: [type: string, label: string][] = [
    ["O", "Organization"],
    ["CN", "Common name"],
    ["OU", "Organizational unit"],
    ["1.3.6.1.4.1.53087.1.6", "Word mark"],
    ["1.3.6.1.4.1.53087.1.13", "Mark type"],
    ["1.3.6.1.4.1.53087.1.4", "Trademark registration"],
    ["1.3.6.1.4.1.53087.1.2", "Trademark office"],
    ["1.3.6.1.4.1.53087.1.3", "Trademark country"],
    ["1.3.6.1.4.1.53087.3.2", "Statute citation"],
    ["1.3.6.1.4.1.53087.3.3", "Statute URL"],
    ["1.3.6.1.4.1.53087.3.5", "Statute country"],
    ["1.3.6.1.4.1.53087.3.6", "Statute state"],
    ["1.3.6.1.4.1.53087.3.7", "Statute locality"],
    ["1.3.6.1.4.1.53087.3.4", "Pilot identifier"],
    ["2.5.4.15", "Business category"],
    ["SERIALNUMBER", "Registration number"],
    ["1.3.6.1.4.1.53087.1.5", "Legal entity identifier"],
    ["1.3.6.1.4.1.311.60.2.1.3", "Jurisdiction country"],
    ["1.3.6.1.4.1.311.60.2.1.2", "Jurisdiction state"],
    ["1.3.6.1.4.1.311.60.2.1.1", "Jurisdiction locality"],
    ["STREET", "Street"],
    ["POSTALCODE", "Postal code"],
    ["L", "Locality"],
    ["ST", "State or province"],
    ["C", "Country"],
];

const labels = new Map(known);
const rank = new Map(known.map(([type], i) => [type, i]));

/**
 * Decodes the hex-encoded DER value an attribute of unknown type is given as
 * ("#0c03414243"), when it is a string. Anything else stays as it was written.
 */
function decodeDer(hex: string): string | undefined {
    if (!/^([0-9a-f]{2})+$/i.test(hex)) return undefined;
    const bytes = Uint8Array.from(hex.match(/../g)!, (b) => parseInt(b, 16));
    if (bytes.length < 2) return undefined;

    let length = bytes[1];
    let offset = 2;
    if (length & 0x80) {
        const n = length & 0x7f;
        if (n === 0 || n > 3 || bytes.length < 2 + n) return undefined;
        length = 0;
        for (let i = 0; i < n; i++) length = (length << 8) | bytes[2 + i];
        offset += n;
    }
    const content = bytes.subarray(offset, offset + length);
    if (content.length !== length) return undefined;

    switch (bytes[0]) {
        case 0x0c: // UTF8String
            return new TextDecoder("utf-8").decode(content);
        case 0x13: // PrintableString
        case 0x16: // IA5String
        case 0x14: // TeletexString, read as Latin-1 as everyone does
            return new TextDecoder("latin1").decode(content);
        case 0x1e: // BMPString
            return new TextDecoder("utf-16be").decode(content);
        default:
            return undefined;
    }
}

/**
 * Takes apart a distinguished name as Go's pkix.Name.String() writes it (RFC 2253:
 * "CN=Example,O=Example\, Inc.,1.3.6.1.4.1.53087.1.13=#0c0f…"), the attributes in
 * the order they are written. A value whose type is only known by OID is decoded
 * when it is a string, so a mark certificate's trademark reads as text.
 */
export function parseDistinguishedName(dn: string): NameAttribute[] {
    // Split on the separators that are not escaped, unescaping as we go
    const parts: string[] = [];
    let current = "";
    for (let i = 0; i < dn.length; i++) {
        const c = dn[i];
        if (c === "\\" && i + 1 < dn.length) {
            current += dn[++i];
        } else if (c === "," || c === "+") {
            parts.push(current);
            current = "";
        } else {
            current += c;
        }
    }
    if (current) parts.push(current);

    return parts.flatMap((part) => {
        const eq = part.indexOf("=");
        if (eq <= 0) return [];
        const type = part.slice(0, eq).trim();
        let value = part.slice(eq + 1);
        if (value.startsWith("#")) value = decodeDer(value.slice(1)) ?? value;
        return [{ type, label: labels.get(type.toUpperCase()) ?? type, value }];
    });
}

/**
 * The attributes in the order a reader looks for them, those of unknown type last,
 * each kind keeping the order it was written in.
 */
export function inReadingOrder(attributes: NameAttribute[]): NameAttribute[] {
    const at = (a: NameAttribute) => rank.get(a.type.toUpperCase()) ?? known.length;
    return [...attributes].sort((a, b) => at(a) - at(b));
}

/** The one value of a name a reader recognises it by: the organization, or its common name. */
export function displayName(attributes: NameAttribute[]): string | undefined {
    const find = (type: string) => attributes.find((a) => a.type.toUpperCase() === type)?.value;
    return find("O") ?? find("CN");
}
