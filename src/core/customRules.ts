// User-defined detection rules (veilo.customPatterns). Compiled defensively so a malformed entry
// never throws — bad rules are skipped and reported. Pure and vscode-free.

import { Category, Severity } from './types';

export interface CustomRule {
    name: string;
    pattern: string;
    flags?: string;
    score?: number;
    category?: Category;
    severity?: Severity;
    description?: string;
}

export interface CompiledCustomRule {
    name: string;
    regex: RegExp;
    score: number;
    category: Category;
    severity: Severity;
    description: string;
}

const CATEGORIES: Category[] = ['secret', 'pii', 'security'];
const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

// Validate and compile raw user input. Returns the usable rules plus human-readable errors for
// anything skipped (bad regex, missing name/pattern, etc.).
export function compileCustomRules(raw: unknown): { rules: CompiledCustomRule[]; errors: string[] } {
    const rules: CompiledCustomRule[] = [];
    const errors: string[] = [];
    if (!Array.isArray(raw)) return { rules, errors };

    raw.forEach((entry, i) => {
        const r = entry as Partial<CustomRule>;
        if (!r || typeof r.name !== 'string' || typeof r.pattern !== 'string') {
            errors.push(`customPatterns[${i}]: requires string "name" and "pattern"`);
            return;
        }
        const flags = typeof r.flags === 'string' ? r.flags : 'g';
        let regex: RegExp;
        try {
            regex = new RegExp(r.pattern, flags.includes('d') ? flags : flags + 'd');
        } catch (e) {
            errors.push(`customPatterns[${i}] (${r.name}): invalid regex — ${(e as Error).message}`);
            return;
        }
        const category = CATEGORIES.includes(r.category as Category) ? (r.category as Category) : 'secret';
        const severity = SEVERITIES.includes(r.severity as Severity) ? (r.severity as Severity) : 'HIGH';
        const score = typeof r.score === 'number' ? r.score : 0.9;
        rules.push({
            name: r.name,
            regex,
            score,
            category,
            severity,
            description: typeof r.description === 'string' ? r.description : `Custom rule: ${r.name}`,
        });
    });

    return { rules, errors };
}
