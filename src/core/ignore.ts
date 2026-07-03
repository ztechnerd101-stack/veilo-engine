// Pure, vscode-free path-ignore logic shared by the editor's IgnoreList and the headless
// commit-hook CLI. Keeps editor squiggles and the pre-commit hook in agreement about which
// files Veilo skips entirely (built-ins, .gitignore, and veilo.ignorePatterns).

import * as fs from 'fs';
import * as path from 'path';

// Always skipped regardless of user config or .gitignore.
export const BUILTIN_IGNORE = [
    '**/node_modules/**',
    '**/.git/**',
    '**/dist/**',
    '**/out/**',
    '**/build/**',
    '**/coverage/**',
    '**/.venv/**',
    '**/vendor/**',
    '**/__pycache__/**',
    '**/*.min.js',
    '**/*.map',
];

// Convert a gitignore-style pattern into a test function over repo-relative POSIX paths.
// Rules:
//   - Pattern with no '/' matches any path segment (filename anywhere in tree)
//   - Pattern with '/' matches from the workspace root
//   - '**' matches zero or more path segments
//   - '*' matches anything except '/'
//   - Trailing '/' means directory — we strip it and match the name
export function patternToMatcher(pattern: string): (rel: string) => boolean {
    let p = pattern.replace(/\/$/, ''); // strip trailing slash
    const anchored = p.includes('/') && !p.startsWith('**/');

    // Escape regex metacharacters except * and ?
    let re = p.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    // Order matters: `**/` (zero or more leading dirs) before bare `**`, both before `*`.
    re = re
        .replace(/\*\*\//g, '\x01') // **/ ⇒ optional any-directory prefix
        .replace(/\*\*/g, '\x00')   // **  ⇒ any characters (incl. /)
        .replace(/\*/g, '[^/]*')
        .replace(/\?/g, '[^/]')
        .replace(/\x01/g, '(?:.*/)?')
        .replace(/\x00/g, '.*');

    const regex = anchored
        ? new RegExp(`^${re}(/.*)?$`)
        : new RegExp(`(^|/)${re}(/.*)?$`);

    return (rel: string) => regex.test(rel);
}

// Read non-negated, non-comment patterns from <workspaceRoot>/.gitignore (if present).
export function readGitignorePatterns(workspaceRoot: string): string[] {
    const patterns: string[] = [];
    try {
        const lines = fs.readFileSync(path.join(workspaceRoot, '.gitignore'), 'utf8').split('\n');
        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith('#') && !trimmed.startsWith('!')) {
                patterns.push(trimmed);
            }
        }
    } catch {
        // No .gitignore — fine.
    }
    return patterns;
}

// Build a predicate over repo-relative paths that combines built-ins, the caller's extra
// patterns (e.g. veilo.ignorePatterns), and the workspace .gitignore.
export function buildPathIgnore(
    workspaceRoot: string | undefined,
    userPatterns: string[] = [],
): (relPath: string) => boolean {
    const patterns = [...BUILTIN_IGNORE, ...userPatterns];
    if (workspaceRoot) {
        patterns.push(...readGitignorePatterns(workspaceRoot));
    }
    const matchers = patterns.map(patternToMatcher);
    return (relPath: string) => {
        const rel = relPath.replace(/\\/g, '/');
        return matchers.some(match => match(rel));
    };
}
