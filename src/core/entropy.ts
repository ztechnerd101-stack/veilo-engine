// High-entropy generic secret detection — a backstop for secrets whose format isn't covered by a
// named rule (e.g. a bespoke internal token). Pure and vscode-free. Deliberately conservative to
// keep false positives low; it is opt-in (see veilo.detectHighEntropy).

// Shannon entropy in bits per character.
export function shannonEntropy(s: string): number {
    if (!s) return 0;
    const freq = new Map<string, number>();
    for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
    let e = 0;
    for (const count of freq.values()) {
        const p = count / s.length;
        e -= p * Math.log2(p);
    }
    return e;
}

export interface EntropyHit { start: number; end: number; value: string; }

// Token shapes that look like keys/tokens: base64/hex/url-safe runs of 24+ chars.
const TOKEN_RE = /[A-Za-z0-9+/_=\-]{24,}/g;

// Find long, mixed-charset, high-entropy tokens. Requires both letters and digits and a per-char
// entropy above `minEntropy` (~3.6 bits filters out repetitive or word-like strings).
export function findHighEntropyTokens(text: string, minEntropy = 3.6): EntropyHit[] {
    const hits: EntropyHit[] = [];
    TOKEN_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = TOKEN_RE.exec(text)) !== null) {
        const value = m[0];
        if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) continue; // need letters + digits
        if (shannonEntropy(value) < minEntropy) continue;
        hits.push({ start: m.index, end: m.index + value.length, value });
    }
    return hits;
}
