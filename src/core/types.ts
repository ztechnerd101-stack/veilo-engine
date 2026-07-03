// vscode-free types shared by the extension detectors and the headless CLI scanner.

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type Category = 'secret' | 'pii' | 'security';

// Offset-based finding produced by the pure (vscode-free) scanners.
// The extension wraps these into `Finding` with a vscode.Range; the CLI converts
// offsets into line/col itself.
export interface RawFinding {
    name: string;
    description: string;
    start: number;
    end: number;
    score: number;
    category: Category;
    severity: Severity;
    advice?: string;
    cwe?: string;
}
