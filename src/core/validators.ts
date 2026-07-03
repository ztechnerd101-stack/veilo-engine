// Pure, dependency-free post-match validators used to drop false positives for patterns
// that have a checksum (credit cards, IBANs). A validator receives the matched value and
// returns true when the value is plausibly real.

// Luhn checksum — credit/debit card numbers. Non-digits (spaces/dashes) are stripped first.
export function luhn(value: string): boolean {
    const digits = value.replace(/\D/g, '');
    if (digits.length < 12 || digits.length > 19) return false;
    let sum = 0;
    let double = false;
    for (let i = digits.length - 1; i >= 0; i--) {
        let n = digits.charCodeAt(i) - 48; // '0' === 48
        if (double) {
            n *= 2;
            if (n > 9) n -= 9;
        }
        sum += n;
        double = !double;
    }
    return sum % 10 === 0;
}

// IBAN mod-97 check (ISO 7064). Whitespace is stripped; basic structure is validated.
export function iban97(value: string): boolean {
    const s = value.replace(/\s+/g, '').toUpperCase();
    if (s.length < 15 || s.length > 34) return false;
    if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(s)) return false;
    // Move the first four chars to the end, map letters to numbers (A=10 … Z=35), then mod 97 === 1.
    const rearranged = s.slice(4) + s.slice(0, 4);
    let remainder = 0;
    for (let i = 0; i < rearranged.length; i++) {
        const c = rearranged.charCodeAt(i);
        const chunk = c >= 65 && c <= 90 ? String(c - 55) : String.fromCharCode(c);
        for (let j = 0; j < chunk.length; j++) {
            remainder = (remainder * 10 + (chunk.charCodeAt(j) - 48)) % 97;
        }
    }
    return remainder === 1;
}
