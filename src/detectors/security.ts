/**
 * VS Code integration layer.
 * Requires the `vscode` extension API — will not compile or run standalone.
 * The underlying detection logic (pattern matching, entropy analysis, checksum
 * validation) lives in ../core/ and IS standalone-runnable.
 * This file is included for reference: it shows how core/ is wired into the editor.
 */
import * as vscode from 'vscode';
import { Finding } from '../types';
import { Severity } from '../core/types';
import { scanSecurityText } from '../core/scan';

export const SEVERITY_TO_DIAGNOSTIC: Record<Severity, vscode.DiagnosticSeverity> = {
    CRITICAL: vscode.DiagnosticSeverity.Error,
    HIGH:     vscode.DiagnosticSeverity.Error,
    MEDIUM:   vscode.DiagnosticSeverity.Warning,
    LOW:      vscode.DiagnosticSeverity.Information,
    INFO:     vscode.DiagnosticSeverity.Hint,
};

// Thin vscode wrapper over the pure core scanner.
export function scanSecurity(document: vscode.TextDocument): Finding[] {
    return scanSecurityText(document.getText(), { filePath: document.uri.fsPath }).map(r => ({
        name: r.name,
        description: r.description,
        range: new vscode.Range(document.positionAt(r.start), document.positionAt(r.end)),
        score: r.score,
        category: r.category,
        severity: r.severity,
        advice: r.advice,
        cwe: r.cwe,
    }));
}