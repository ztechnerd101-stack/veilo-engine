// Pure, vscode-free scanning logic shared by the extension detectors and the headless CLI.

import { RawFinding } from './types';
import { SECRET_PATTERNS, SecretPatternDef } from './patterns/secrets';
import { PII_PATTERNS, PiiPatternDef } from './patterns/pii';
import { EXPLOIT_RULES, ExploitRule } from './patterns/security';
import { patternToMatcher } from './ignore';
import { findHighEntropyTokens } from './entropy';
import { CompiledCustomRule } from './customRules';

// Optional context for a scan. `filePath` (repo-relative or absolute, either slash style) lets
// rules with an `appliesTo` glob restrict themselves to the files they're relevant for.
export interface ScanOptions {
    filePath?: string;
    // When true, run the high-entropy generic-secret backstop (opt-in; off by default).
    entropy?: boolean;
}

// Prefer capture group 1 (the sensitive value) when present; otherwise fall back to the full
// match. Requires the regex to be compiled with the `d` (hasIndices) flag — see withIndices().
export function valueRange(match: RegExpExecArray): [number, number] {
    const g1 = match.indices?.[1];
    if (g1) return [g1[0], g1[1]];
    return [match.index, match.index + match[0].length];
}

function withIndices(flags: string): string {
    return flags.includes('d') ? flags : flags + 'd';
}

// A rule paired with its compiled regex and (optional) compiled appliesTo matchers, built once at
// module load instead of recompiling on every scan (detectors run on every save/open).
interface Compiled<T extends RuleDef> {
    def: T;
    regex: RegExp;
    appliesTo?: Array<(rel: string) => boolean>;
}

interface RuleDef {
    pattern: string;
    flags: string;
    appliesTo?: string[];
    validate?: (value: string) => boolean;
}

function compileRules<T extends RuleDef>(defs: T[]): Compiled<T>[] {
    return defs.map(def => ({
        def,
        regex: new RegExp(def.pattern, withIndices(def.flags)),
        appliesTo: def.appliesTo?.map(patternToMatcher),
    }));
}

const COMPILED_SECRETS = compileRules<SecretPatternDef>(SECRET_PATTERNS);
const COMPILED_PII = compileRules<PiiPatternDef>(PII_PATTERNS);
const COMPILED_SECURITY = compileRules<ExploitRule>(EXPLOIT_RULES);

// A rule with no appliesTo runs everywhere. A scoped rule runs only when we know the file and one
// of its globs matches — when the file is unknown we conservatively skip it (so file-specific
// rules like requirements.txt checks don't fire on arbitrary text).
function ruleApplies(appliesTo: Array<(rel: string) => boolean> | undefined, filePath?: string): boolean {
    if (!appliesTo || appliesTo.length === 0) return true;
    if (!filePath) return false;
    const rel = filePath.replace(/\\/g, '/');
    return appliesTo.some(match => match(rel));
}

// Inline suppression directives (place anywhere in a comment). Both the `veilo-ignore`
// and the ESLint-style `veilo-disable` spellings are accepted so they read naturally for
// any dev:
//   veilo-ignore            / veilo-disable-line       — suppress findings on this line
//   veilo-ignore-next-line  / veilo-disable-next-line  — suppress findings on the next line
//   veilo-ignore-file       / veilo-disable-file       — suppress the entire file
// Returns a predicate that reports whether a finding at the given offset is suppressed.
export function buildSuppressor(text: string): (offset: number) => boolean {
    const lineStarts: number[] = [0];
    for (let i = 0; i < text.length; i++) {
        if (text.charCodeAt(i) === 10) lineStarts.push(i + 1);
    }

    // Matches "veilo-ignore" / "veilo-disable" with an optional -file / -next[-line] / -line suffix.
    const directive = /veilo-(?:ignore|disable)(-file|-next(?:-line)?|-line)?/;

    const ignored = new Set<number>();
    let fileIgnored = false;
    const rows = text.split('\n');
    for (let i = 0; i < rows.length; i++) {
        const m = directive.exec(rows[i]);
        if (!m) continue;
        const suffix = m[1];
        if (suffix === '-file') {
            fileIgnored = true;
        } else if (suffix && suffix.startsWith('-next')) {
            ignored.add(i + 1); // 0-based index of the next line
        } else {
            ignored.add(i); // bare directive or -line ⇒ this line
        }
    }

    const lineOf = (offset: number): number => {
        let lo = 0, hi = lineStarts.length - 1;
        while (lo < hi) {
            const mid = (lo + hi + 1) >> 1;
            if (lineStarts[mid] <= offset) lo = mid; else hi = mid - 1;
        }
        return lo;
    };

    return (offset: number) => fileIgnored || ignored.has(lineOf(offset));
}

export function scanSecretsText(text: string, scoreThreshold = 0.7, opts: ScanOptions = {}): RawFinding[] {
    const findings: RawFinding[] = [];
    const covered: Array<[number, number]> = [];
    const suppressed = buildSuppressor(text);

    for (const { def, regex, appliesTo } of COMPILED_SECRETS) {
        if (def.score < scoreThreshold) continue;
        if (!ruleApplies(appliesTo, opts.filePath)) continue;

        regex.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = regex.exec(text)) !== null) {
            const [start, end] = valueRange(match);
            if (end === start) continue; // guard against zero-width matches
            if (def.validate && !def.validate(text.slice(start, end))) continue;
            if (suppressed(start)) continue;

            if (covered.some(([s, e]) => s < end && e > start)) continue;
            covered.push([start, end]);

            findings.push({
                name: def.name,
                description: def.description,
                start, end,
                score: def.score,
                category: 'secret',
                severity: 'CRITICAL',
            });
        }
    }

    // Generic high-entropy backstop (opt-in). Runs last so anything a named rule already covered
    // is skipped via the `covered` overlap check, and respects inline suppression.
    if (opts.entropy) {
        for (const hit of findHighEntropyTokens(text)) {
            if (0.7 < scoreThreshold) break; // entropy findings score 0.7; honor the threshold
            if (suppressed(hit.start)) continue;
            if (covered.some(([s, e]) => s < hit.end && e > hit.start)) continue;
            covered.push([hit.start, hit.end]);
            findings.push({
                name: 'GENERIC_HIGH_ENTROPY',
                description: 'High-entropy string — may be a secret/token in an unrecognized format.',
                start: hit.start, end: hit.end,
                score: 0.7,
                category: 'secret',
                severity: 'HIGH',
            });
        }
    }

    return findings;
}

export function scanPiiText(text: string, scoreThreshold = 0.7, opts: ScanOptions = {}): RawFinding[] {
    const findings: RawFinding[] = [];
    const covered: Array<[number, number]> = [];
    const suppressed = buildSuppressor(text);

    for (const { def, regex, appliesTo } of COMPILED_PII) {
        if (def.score < scoreThreshold) continue;
        if (!ruleApplies(appliesTo, opts.filePath)) continue;

        regex.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = regex.exec(text)) !== null) {
            const [start, end] = valueRange(match);
            if (end === start) continue;
            if (def.validate && !def.validate(text.slice(start, end))) continue;
            if (suppressed(start)) continue;

            if (covered.some(([s, e]) => s < end && e > start)) continue;
            covered.push([start, end]);

            findings.push({
                name: def.name,
                description: def.description,
                start, end,
                score: def.score,
                category: 'pii',
                severity: 'HIGH',
            });
        }
    }

    return findings;
}

export function scanSecurityText(text: string, opts: ScanOptions = {}): RawFinding[] {
    const findings: RawFinding[] = [];
    const seenRuleLine = new Set<string>();
    const suppressed = buildSuppressor(text);

    for (const { def: rule, regex, appliesTo } of COMPILED_SECURITY) {
        if (!ruleApplies(appliesTo, opts.filePath)) continue;

        regex.lastIndex = 0;
        let match: RegExpExecArray | null;

        while ((match = regex.exec(text)) !== null) {
            const [start, end] = valueRange(match);
            if (end === start) {
                // Zero-width match (possible with some alternations) — advance to avoid a loop.
                regex.lastIndex++;
                continue;
            }
            if (rule.validate && !rule.validate(text.slice(start, end))) continue;
            if (suppressed(start)) continue;

            // Dedupe one finding per rule per line.
            const lineNum = lineAt(text, start);
            const dedupeKey = `${rule.ruleId}:${lineNum}`;
            if (seenRuleLine.has(dedupeKey)) continue;
            seenRuleLine.add(dedupeKey);

            findings.push({
                name: rule.ruleId,
                description: `${rule.title}: ${rule.description}`,
                start, end,
                score: 1.0,
                category: 'security',
                severity: rule.severity,
                advice: rule.advice,
                cwe: rule.cwe,
            });
        }
    }

    return findings;
}

// Run user-defined custom rules. Shares the same suppression and value-range logic as the built-in
// scanners; one finding per rule per line.
export function scanCustomText(text: string, rules: CompiledCustomRule[]): RawFinding[] {
    const findings: RawFinding[] = [];
    if (rules.length === 0) return findings;
    const suppressed = buildSuppressor(text);
    const seenRuleLine = new Set<string>();

    for (const rule of rules) {
        rule.regex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = rule.regex.exec(text)) !== null) {
            const [start, end] = valueRange(match);
            if (end === start) { rule.regex.lastIndex++; continue; }
            if (suppressed(start)) continue;

            const key = `${rule.name}:${lineAt(text, start)}`;
            if (seenRuleLine.has(key)) continue;
            seenRuleLine.add(key);

            findings.push({
                name: rule.name,
                description: rule.description,
                start, end,
                score: rule.score,
                category: rule.category,
                severity: rule.severity,
            });
        }
    }

    return findings;
}

// Zero-based line number of a character offset.
function lineAt(text: string, offset: number): number {
    let line = 0;
    for (let i = 0; i < offset && i < text.length; i++) {
        if (text.charCodeAt(i) === 10 /* \n */) line++;
    }
    return line;
}
