import * as vscode from 'vscode';

export interface Finding {
    name: string;
    description: string;
    range: vscode.Range;
    score: number;
    category: 'secret' | 'pii' | 'security';
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    advice?: string;
    cwe?: string;
}