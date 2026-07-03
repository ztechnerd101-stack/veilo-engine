// veilo-ignore-file — this file *defines* the detection rules; the literals below are not real PII.
// vscode-free PII-detection pattern data. Shared by the extension detector and the CLI.
// Regex recognizers only (no spaCy NER). PERSON / LOCATION / ORG are intentionally omitted:
// they don't appear meaningfully in code.

import { luhn, iban97 } from '../validators';

export interface PiiPatternDef {
    name: string;
    pattern: string;
    flags: string;
    score: number;
    description: string;
    // Optional gitignore-style globs; when set, the rule only runs on matching files.
    appliesTo?: string[];
    // Optional post-match check (e.g. Luhn / IBAN mod-97); a finding is dropped when it returns false.
    validate?: (value: string) => boolean;
}

export const PII_PATTERNS: PiiPatternDef[] = [
    {
        name: 'EMAIL',
        pattern: '[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}',
        flags: 'g', score: 0.9,
        description: 'Email Address',
    },
    {
        name: 'IBAN',
        // Allows optional spaces every 4 chars e.g. AE07 0331 2345 6789 0123 456
        pattern: '\\b[A-Z]{2}\\d{2}(?:\\s?[A-Z0-9]{4}){1,7}(?:\\s?[A-Z0-9]{1,4})?\\b',
        flags: 'g', score: 0.95,
        description: 'IBAN Bank Account Number',
        validate: iban97, // mod-97 check drops random uppercase/digit runs
    },
    {
        name: 'CREDIT_CARD',
        // Visa, Mastercard, Amex, Discover + spaced/dashed format
        // Negative lookbehind prevents matching IBAN prefix
        pattern: '(?<![A-Z]{2}\\d{2}\\s)(?<![A-Z]{2}\\d{2})\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:\\d{4}[- ]){3}\\d{4})\\b',
        flags: 'g', score: 0.85,
        description: 'Credit/Debit Card Number',
        validate: luhn, // Luhn checksum drops 16-digit numbers that aren't real cards
    },
    {
        name: 'SSN',
        // Excludes structurally-invalid SSNs: area 000/666/9xx, group 00, serial 0000.
        pattern: '\\b(?!000|666|9\\d\\d)\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b',
        flags: 'g', score: 0.85,
        description: 'US Social Security Number',
    },
    {
        name: 'US_ITIN',
        // Individual Taxpayer Identification Number — 9XX-7X-XXXX
        pattern: '\\b9\\d{2}-[7-9]\\d-\\d{4}\\b',
        flags: 'g', score: 0.8,
        description: 'US ITIN',
    },
    {
        name: 'US_EIN',
        pattern: '(?:ein|employer[_\\s-]?id)\\s*[=:]?\\s*(\\d{2}-\\d{7})\\b',
        flags: 'gi', score: 0.8,
        description: 'US Employer Identification Number',
    },
    {
        name: 'UAE_ID',
        pattern: '\\b784-\\d{4}-\\d{7}-\\d{1}\\b',
        flags: 'g', score: 0.95,
        description: 'UAE National ID',
    },
    {
        name: 'SAUDI_ID',
        // Saudi national / iqama id: 10 digits starting with 1 or 2, on a labeled assignment
        pattern: '(?:iqama|national[_\\s-]?id|saudi[_\\s-]?id)\\s*[=:]?\\s*([12]\\d{9})\\b',
        flags: 'gi', score: 0.85,
        description: 'Saudi National ID / Iqama',
    },
    {
        name: 'IPV4',
        pattern: '\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b',
        flags: 'g', score: 0.85,
        description: 'IPv4 Address',
    },
    {
        name: 'IPV6',
        // Full form plus the common compressed (::) variants. Bounded by non-hex/colon on each side.
        pattern: '(?<![0-9A-Fa-f:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6})(?![0-9A-Fa-f:])',
        flags: 'g', score: 0.85,
        description: 'IPv6 Address',
    },
    {
        name: 'MAC_ADDRESS',
        pattern: '\\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b',
        flags: 'g', score: 0.7,
        description: 'MAC Address',
    },
    {
        name: 'PHONE_INTL',
        // Must start with + and not be preceded by letters (rules out IBAN prefix like AE07)
        pattern: '(?<![A-Z0-9])\\+\\d[\\d\\s\\-(). ]{6,20}\\d',
        flags: 'g', score: 0.75,
        description: 'Phone Number (International)',
    },
    {
        name: 'PHONE_US',
        // (123) 456-7890 / 123-456-7890 / 123.456.7890
        pattern: '(?<![\\d.])\\(?\\b[2-9]\\d{2}\\)?[\\s.\\-]\\d{3}[\\s.\\-]\\d{4}\\b',
        flags: 'g', score: 0.7,
        description: 'Phone Number (US)',
    },
    {
        name: 'PASSPORT',
        // Label-gated: a bare 2-letter+7-digit token matches far too much (SKUs, plates, IDs).
        pattern: 'passport\\s*(?:number|no\\.?|#)?\\s*[=:]\\s*[\'"]?([A-Z]{2}[0-9]{7})\\b',
        flags: 'gi', score: 0.8,
        description: 'Passport Number (International)',
    },
    {
        name: 'DATE_OF_BIRTH',
        pattern: '\\b(?:dob|date[_\\-\\s]?of[_\\-\\s]?birth|birthday)\\s*[=:\\s]+(\\d{1,2}[\\/-]\\d{1,2}[\\/-]\\d{2,4})\\b',
        flags: 'gi', score: 0.8,
        description: 'Date of Birth',
    },
];
