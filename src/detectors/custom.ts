/**
 * VS Code integration layer.
 * Requires the `vscode` extension API — will not compile or run standalone.
 * The underlying detection logic (pattern matching, entropy analysis, checksum
 * validation) lives in ../core/ and IS standalone-runnable.
 * This file is included for reference: it shows how core/ is wired into the editor.
 */
import * as vscode from 'vscode';
import { Finding } from '../types';
import { scanCustomText } from '../core/scan';
import { CompiledCustomRule } from '../core/customRules';

// Thin vscode wrapper running user-defined custom rules over the document.
export function scanCustom(document: vscode.TextDocument, rules: CompiledCustomRule[]): Finding[] {
    if (rules.length === 0) return [];
    return scanCustomText(document.getText(), rules).map(r => ({
        name: r.name,
        description: r.description,
        range: new vscode.Range(document.positionAt(r.start), document.positionAt(r.end)),
        score: r.score,
        category: r.category,
        severity: r.severity,
    }));
}