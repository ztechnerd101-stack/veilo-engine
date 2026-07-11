// veilo-ignore-file — this file *defines* the detection rules; the literals below are not real vulnerabilities.
// vscode-free security-rule data. Shared by the extension detector and the CLI.

import { Severity } from '../types';

export interface ExploitRule {
    ruleId: string;
    title: string;
    description: string;
    severity: Severity;
    pattern: string;
    flags: string;
    cwe: string;
    advice: string;
    // Optional gitignore-style globs; when set, the rule only runs on matching files
    // (e.g. dependency manifests for the unpinned-dependency rule).
    appliesTo?: string[];
    // Optional post-match check; a finding is dropped when this returns false.
    validate?: (value: string) => boolean;
}

export const EXPLOIT_RULES: ExploitRule[] = [

    // ── Injection ────────────────────────────────────────────────────────
    {
        ruleId: 'VEILO-001', title: 'SQL Injection Risk',
        description: 'String formatting or concatenation used to build SQL query.',
        severity: 'CRITICAL',
        // f-string branch requires an actual SQL clause pair (SELECT…FROM etc.), not a lone keyword —
        // otherwise ordinary words like "updated"/"deleted"/"selected" (which contain UPDATE/DELETE/SELECT)
        // trip it. Keywords are \b-anchored so substrings inside longer words no longer match.
        pattern: '(?:execute|cursor\\.execute|query|raw)\\s*\\(\\s*[\'"].*?[\'"].*?%|f[\'"][^\'"]*\\b(?:SELECT\\b[^\'"]*\\bFROM|INSERT\\b[^\'"]*\\bINTO|UPDATE\\b[^\'"]*\\bSET|DELETE\\b[^\'"]*\\bFROM)\\b',
        flags: 'gi',
        cwe: 'CWE-89', advice: 'Use parameterized queries or an ORM instead of string formatting.',
    },
    {
        ruleId: 'VEILO-002', title: 'Command Injection Risk',
        description: 'User-controlled input may be passed to a shell command.',
        severity: 'CRITICAL',
        pattern: '(?:os\\.system|subprocess\\.call|subprocess\\.run|popen)\\s*\\(\\s*(?:f[\'"]|[\'"].*?\\+|.*?format)',
        flags: 'g',
        cwe: 'CWE-78', advice: 'Avoid shell=True. Use subprocess with a list of arguments and validate all input.',
    },
    {
        ruleId: 'VEILO-003', title: 'LDAP Injection Risk',
        description: 'Unescaped input used in LDAP filter construction.',
        severity: 'HIGH',
        pattern: 'ldap.*search.*filter.*[+%]|ldap.*filter.*format',
        flags: 'gi',
        cwe: 'CWE-90', advice: 'Use an LDAP library that supports parameterized filters and escape all user input.',
    },
    {
        ruleId: 'VEILO-004', title: 'XPath Injection Risk',
        description: 'Unescaped input used in XPath expression.',
        severity: 'HIGH',
        pattern: 'xpath.*[+%].*input|find\\(.*f[\'"]',
        flags: 'gi',
        cwe: 'CWE-643', advice: 'Sanitize all user input before including in XPath expressions.',
    },

    // ── Cryptography ─────────────────────────────────────────────────────
    {
        ruleId: 'VEILO-005', title: 'Weak Hashing Algorithm',
        description: 'MD5 or SHA1 used — both are cryptographically broken.',
        severity: 'HIGH',
        pattern: 'hashlib\\.(?:md5|sha1)\\s*\\(|(?:md5|sha1)\\s*\\(',
        flags: 'gi',
        cwe: 'CWE-327', advice: 'Use SHA-256 or stronger. For passwords, use bcrypt, scrypt, or argon2.',
    },
    {
        ruleId: 'VEILO-006', title: 'Hardcoded Salt or IV',
        description: 'Static salt or initialization vector detected — weakens encryption.',
        severity: 'HIGH',
        pattern: '(?:salt|iv|nonce)\\s*=\\s*[\'"][^\'"]{4,}[\'"]',
        flags: 'gi',
        cwe: 'CWE-760', advice: 'Generate cryptographic salt/IV randomly using os.urandom() or secrets module.',
    },
    {
        ruleId: 'VEILO-007', title: 'Insecure Random Number Generator',
        description: 'random module used for security-sensitive context.',
        severity: 'MEDIUM',
        // Only the actual calls — a bare `import random` flagged every file and was pure noise.
        pattern: 'random\\.(?:random|randint|randrange|uniform|choice|getrandbits|seed|shuffle)\\s*\\(',
        flags: 'g',
        cwe: 'CWE-338', advice: 'Use the secrets module for security-sensitive random values.',
    },

    // ── Deserialization ───────────────────────────────────────────────────
    {
        ruleId: 'VEILO-008', title: 'Unsafe Deserialization (pickle)',
        description: 'pickle.loads() on untrusted data allows arbitrary code execution.',
        severity: 'CRITICAL',
        pattern: 'pickle\\.loads?\\s*\\(',
        flags: 'g',
        cwe: 'CWE-502', advice: 'Never unpickle data from untrusted sources. Use JSON or protobuf instead.',
    },
    {
        ruleId: 'VEILO-009', title: 'Unsafe YAML Load',
        description: 'yaml.load() without Loader can execute arbitrary Python.',
        severity: 'CRITICAL',
        pattern: 'yaml\\.load\\s*\\((?!.*Loader=yaml\\.SafeLoader)',
        flags: 'g',
        cwe: 'CWE-502', advice: 'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) instead.',
    },
    {
        ruleId: 'VEILO-010', title: 'Unsafe eval() Usage',
        description: 'eval() on dynamic or user-controlled input is a code injection vector.',
        severity: 'CRITICAL',
        pattern: '\\beval\\s*\\(\\s*(?![\'"])',
        flags: 'g',
        cwe: 'CWE-95', advice: 'Avoid eval() entirely. Use ast.literal_eval() for safe expression parsing.',
        appliesTo: ['*.py', '*.pyw'], // JS eval is covered by VEILO-021 — avoids double-reporting
    },

    // ── Network & TLS ─────────────────────────────────────────────────────
    {
        ruleId: 'VEILO-011', title: 'TLS Certificate Verification Disabled',
        description: 'SSL/TLS certificate verification is turned off — enables MITM attacks.',
        severity: 'CRITICAL',
        pattern: 'verify\\s*=\\s*False|ssl_verify\\s*=\\s*False|check_hostname\\s*=\\s*False|rejectUnauthorized\\s*:\\s*false',
        flags: 'gi',
        cwe: 'CWE-295', advice: 'Never disable certificate verification in production. Fix the certificate instead.',
    },
    {
        ruleId: 'VEILO-012', title: 'Hardcoded HTTP URL',
        description: 'Plain HTTP URL detected — traffic is unencrypted.',
        severity: 'MEDIUM',
        pattern: '[\'"]http://(?!localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0)[^\'"]{4,}[\'"]',
        flags: 'g',
        cwe: 'CWE-319', advice: 'Use HTTPS for all external endpoints.',
    },
    {
        ruleId: 'VEILO-013', title: 'Binding to All Interfaces',
        description: 'Server binding to 0.0.0.0 exposes it on all network interfaces.',
        severity: 'MEDIUM',
        pattern: '[\'"]0\\.0\\.0\\.0[\'"]',
        flags: 'g',
        cwe: 'CWE-605', advice: 'Bind to 127.0.0.1 in development. Use a reverse proxy in production.',
    },

    // ── Auth & Session ─────────────────────────────────────────────────────
    {
        ruleId: 'VEILO-014', title: 'Hardcoded JWT Secret',
        description: 'JWT signing secret is hardcoded in source — can be extracted.',
        severity: 'CRITICAL',
        pattern: '(?:jwt|token).*secret\\s*=\\s*[\'"][^\'"]{4,}[\'"]',
        flags: 'gi',
        cwe: 'CWE-321', advice: 'Load JWT secrets from environment variables or a secrets manager.',
    },
    {
        ruleId: 'VEILO-015', title: 'Weak Session Secret',
        description: 'Session secret key appears short or predictable.',
        severity: 'HIGH',
        pattern: '(?:secret[_-]?key|session[_-]?secret)\\s*=\\s*[\'"][^\'"]{4,20}[\'"]',
        flags: 'gi',
        cwe: 'CWE-331', advice: 'Use a cryptographically random secret of at least 32 bytes via secrets.token_hex(32).',
    },

    // ── File System ───────────────────────────────────────────────────────
    {
        ruleId: 'VEILO-016', title: 'Path Traversal Risk',
        description: 'User input used in file path without sanitization.',
        severity: 'HIGH',
        // Tightened to request-derived input; bare `data`/`input`/`user` matched ordinary variables.
        pattern: 'open\\s*\\(\\s*(?:request|user_input|userinput)|os\\.path\\.join\\s*\\([^)]*(?:request\\.(?:args|form|files|values|json)|user_input)',
        flags: 'gi',
        cwe: 'CWE-22', advice: 'Validate and sanitize file paths. Use pathlib and ensure the resolved path is within the expected directory.',
    },
    {
        ruleId: 'VEILO-017', title: 'Insecure Temporary File',
        description: 'tempfile.mktemp() is insecure — race condition between creation and use.',
        severity: 'MEDIUM',
        pattern: 'tempfile\\.mktemp\\s*\\(',
        flags: 'g',
        cwe: 'CWE-377', advice: 'Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead.',
    },

    // ── Debug & Logging ───────────────────────────────────────────────────
    {
        ruleId: 'VEILO-018', title: 'Debug Mode Enabled',
        description: 'Debug mode left on — exposes stack traces and internal info.',
        severity: 'HIGH',
        pattern: 'debug\\s*=\\s*True|app\\.run\\s*\\([^)]*debug\\s*=\\s*True',
        flags: 'gi',
        cwe: 'CWE-94', advice: 'Disable debug mode in production. Use environment variables to control this.',
    },
    {
        ruleId: 'VEILO-019', title: 'Sensitive Data in Log Statement',
        description: 'Password, token, or secret may be logged in plaintext.',
        severity: 'HIGH',
        pattern: '(?:console\\s*\\.\\s*\\w+|logger?\\s*\\.\\s*\\w+|logging\\.\\w+|System\\.out\\.print\\w*|\\bprint(?:ln|f)?)\\s*\\([^)\\n]*(?:password|passwd|secret|token|api[_-]?key|credential)',
        flags: 'gi',
        cwe: 'CWE-532', advice: 'Never log sensitive values. Mask or omit them from log output.',
    },

    // ── Dependency & Supply Chain ─────────────────────────────────────────
    {
        ruleId: 'VEILO-020', title: 'Unpinned Dependency',
        description: 'Dependency without pinned version — vulnerable to supply chain attacks.',
        severity: 'LOW',
        pattern: '^(?!#)[\\w\\-]+\\s*(?:>=|<=|~=|!=|>|<)\\s*[\\d.]+\\s*$|^(?!#)[\\w\\-]+\\s*$',
        flags: 'gm',
        cwe: 'CWE-1357', advice: 'Pin all dependencies to exact versions (==) in production.',
        // Scoped to Python requirement files — the bare-word line is valid there, but elsewhere it
        // matched any single-word line (e.g. `function`, `TODO`) and flooded every file.
        appliesTo: ['requirements.txt', 'requirements*.txt', 'requirements/*.txt', 'constraints.txt'],
    },

    // ── JavaScript / Web ──────────────────────────────────────────────────
    {
        ruleId: 'VEILO-021', title: 'Unsafe eval() / Function (JS)',
        description: 'eval() or the Function constructor executes dynamic code.',
        severity: 'CRITICAL',
        pattern: '\\beval\\s*\\(|new\\s+Function\\s*\\(',
        flags: 'g',
        cwe: 'CWE-95', advice: 'Avoid eval()/Function(). Parse data with JSON.parse and use explicit logic.',
        appliesTo: ['*.js', '*.jsx', '*.ts', '*.tsx', '*.mjs', '*.cjs', '*.vue', '*.svelte'],
    },
    {
        ruleId: 'VEILO-022', title: 'Command Injection (Node)',
        description: 'child_process.exec with interpolated input can run arbitrary shell commands.',
        severity: 'CRITICAL',
        pattern: '(?:child_process\\.)?exec(?:Sync)?\\s*\\(\\s*(?:`[^`]*\\$\\{|[\'"][^\'"]*[\'"]\\s*\\+)',
        flags: 'g',
        cwe: 'CWE-78', advice: 'Use execFile/spawn with an argument array instead of building a shell string.',
    },
    {
        ruleId: 'VEILO-023', title: 'Cross-Site Scripting (XSS) Sink',
        description: 'dangerouslySetInnerHTML / innerHTML / document.write with dynamic content.',
        severity: 'HIGH',
        pattern: 'dangerouslySetInnerHTML|\\.innerHTML\\s*=|document\\.write\\s*\\(',
        flags: 'g',
        cwe: 'CWE-79', advice: 'Render text via safe APIs or sanitize HTML with a vetted library (e.g. DOMPurify).',
    },
    {
        ruleId: 'VEILO-024', title: 'Server-Side Template Injection',
        description: 'render_template_string / mark_safe with dynamic input enables SSTI/XSS.',
        severity: 'HIGH',
        pattern: 'render_template_string\\s*\\(|mark_safe\\s*\\(',
        flags: 'g',
        cwe: 'CWE-94', advice: 'Render static templates with bound context; never feed user input into the template source.',
    },
    {
        ruleId: 'VEILO-025', title: 'Permissive CORS Policy',
        description: 'Access-Control-Allow-Origin set to "*" exposes the API to any origin.',
        severity: 'MEDIUM',
        pattern: 'Access-Control-Allow-Origin[\'"]?\\s*[:,]\\s*[\'"]\\*[\'"]|cors\\s*\\(\\s*\\{\\s*origin\\s*:\\s*[\'"]\\*[\'"]',
        flags: 'gi',
        cwe: 'CWE-942', advice: 'Allow only an explicit list of trusted origins.',
    },
];
