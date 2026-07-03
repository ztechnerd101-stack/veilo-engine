/**
 * VS Code integration layer.
 * Requires the `vscode` extension API — will not compile or run standalone.
 * The underlying detection logic (pattern matching, entropy analysis, checksum
 * validation) lives in ../core/ and IS standalone-runnable.
 * This file is included for reference: it shows how core/ is wired into the editor.
 */
import * as vscode from 'vscode';
import { Finding } from '../types';
import { scanSecretsText } from '../core/scan';

// Thin vscode wrapper over the pure core scanner. Pattern data + matching logic live in
// src/core so the headless CLI (pre-commit hook) can share them.
export function scanSecrets(document: vscode.TextDocument, scoreThreshold = 0.7, entropy = false): Finding[] {
    return scanSecretsText(document.getText(), scoreThreshold, { filePath: document.uri.fsPath, entropy }).map(r => ({
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