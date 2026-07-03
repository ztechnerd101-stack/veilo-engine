// veilo-ignore-file — this file *defines* the detection rules; the literals below are not real secrets.
// vscode-free secret-detection pattern data. Shared by the extension detector and the CLI.
// Convention: when a pattern includes a key name / assignment, wrap the sensitive value in
// capture group 1 so the underline (and CLI report) targets the value only.

export interface SecretPatternDef {
    name: string;
    pattern: string;
    flags: string;
    score: number;
    description: string;
    // Optional gitignore-style globs; when set, the rule only runs on matching files.
    appliesTo?: string[];
    // Optional post-match check (e.g. Luhn); a finding is dropped when this returns false.
    validate?: (value: string) => boolean;
}

export const SECRET_PATTERNS: SecretPatternDef[] = [

    // ── Cloud Providers ──────────────────────────────────────────────────
    { name: 'AWS_ACCESS_KEY',      pattern: 'AKIA[0-9A-Z]{16}',                                                                                           flags: 'g',  score: 0.99, description: 'AWS Access Key ID' },
    { name: 'AWS_SECRET_KEY',      pattern: '(?:aws_secret_access_key|aws_secret_key|aws_secret)\\s*[=:]\\s*[\'"]?([A-Za-z0-9\\/+=]{40})[\'"]?',           flags: 'gi', score: 0.95, description: 'AWS Secret Access Key' },
    { name: 'GCP_SERVICE_ACCOUNT', pattern: '"private_key"\\s*:\\s*"(-----BEGIN (?:RSA )?PRIVATE KEY-----[^"]+)"',                                       flags: 'g',  score: 0.99, description: 'GCP Service Account Private Key' },
    { name: 'GOOGLE_API_KEY',      pattern: 'AIza[0-9A-Za-z\\-_]{35}',                                                                                     flags: 'g',  score: 0.95, description: 'Google API Key' },
    { name: 'AZURE_CLIENT_SECRET', pattern: '(?:azure|az)_?(?:client)?_?secret\\s*[=:]\\s*[\'"]?([A-Za-z0-9\\-._~]{32,})[\'"]?',                         flags: 'gi', score: 0.85, description: 'Azure Client Secret' },
    { name: 'DIGITALOCEAN_TOKEN',  pattern: 'dop_v1_[a-f0-9]{64}',                                                                                         flags: 'g',  score: 0.99, description: 'DigitalOcean Personal Access Token' },
    { name: 'HEROKU_API_KEY',      pattern: '(?:heroku)[a-z0-9_ ]{0,20}[=:]\\s*[\'"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\'"]?', flags: 'gi', score: 0.9,  description: 'Heroku API Key' },

    // ── API Keys ─────────────────────────────────────────────────────────
    { name: 'API_KEY',             pattern: '(?:api[_-]?key|apikey|api[_-]?token)\\s*[=:]\\s*[\'"]?([A-Za-z0-9\\-._~+\\/]{16,})[\'"]?',                  flags: 'gi', score: 0.8,  description: 'Generic API Key' },
    { name: 'STRIPE_KEY',          pattern: '(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}',                                                                 flags: 'g',  score: 0.99, description: 'Stripe Secret/Public Key' },
    { name: 'SENDGRID_KEY',        pattern: 'SG\\.[A-Za-z0-9\\-_]{10,}\\.[A-Za-z0-9\\-_]{10,}',                                                          flags: 'g',  score: 0.99, description: 'SendGrid API Key' },
    { name: 'TWILIO_KEY',          pattern: '\\bSK[a-f0-9]{32}\\b',                                                                                        flags: 'g',  score: 0.9,  description: 'Twilio API Key' },
    { name: 'GITHUB_TOKEN',        pattern: 'gh[pousr]_[A-Za-z0-9]{20,}',                                                                                  flags: 'g',  score: 0.99, description: 'GitHub Personal Access Token' },
    { name: 'GITHUB_FINE_TOKEN',   pattern: 'github_pat_[0-9a-zA-Z_]{59,}',                                                                                flags: 'g',  score: 0.99, description: 'GitHub Fine-Grained PAT' },
    { name: 'GITLAB_TOKEN',        pattern: 'glpat-[A-Za-z0-9\\-_]{20,}',                                                                                  flags: 'g',  score: 0.99, description: 'GitLab Personal Access Token' },
    { name: 'SLACK_TOKEN',         pattern: 'xox[baprs]-[A-Za-z0-9\\-]{10,}',                                                                              flags: 'g',  score: 0.99, description: 'Slack Token' },
    { name: 'OPENAI_KEY',          pattern: 'sk-(?:proj-)?[A-Za-z0-9\\-_]{20,}',                                                                           flags: 'g',  score: 0.9,  description: 'OpenAI API Key' },
    { name: 'ANTHROPIC_KEY',       pattern: 'sk-ant-[A-Za-z0-9\\-_]{32,}',                                                                                 flags: 'g',  score: 0.99, description: 'Anthropic API Key' },
    { name: 'MAILCHIMP_KEY',       pattern: '[a-f0-9]{32}-us\\d+',                                                                                         flags: 'g',  score: 0.9,  description: 'Mailchimp API Key' },
    { name: 'MAPBOX_TOKEN',        pattern: 'pk\\.eyJ1[A-Za-z0-9\\-_.]+',                                                                                  flags: 'g',  score: 0.95, description: 'Mapbox Token' },
    { name: 'SQUARE_TOKEN',        pattern: 'sq0(?:atp|csp)-[A-Za-z0-9\\-_]{22,}',                                                                         flags: 'g',  score: 0.95, description: 'Square Access/OAuth Token' },
    { name: 'SHOPIFY_TOKEN',       pattern: 'shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}',                                                                          flags: 'g',  score: 0.99, description: 'Shopify Access Token' },
    { name: 'NPM_TOKEN',           pattern: 'npm_[A-Za-z0-9]{36}',                                                                                         flags: 'g',  score: 0.99, description: 'npm Access Token' },
    { name: 'PYPI_TOKEN',          pattern: 'pypi-AgEIcHlwaS[A-Za-z0-9\\-_]{50,}',                                                                         flags: 'g',  score: 0.99, description: 'PyPI Upload Token' },
    { name: 'DATADOG_KEY',         pattern: '(?:datadog|dd)_?api_?key\\s*[=:]\\s*[\'"]?([a-f0-9]{32})[\'"]?',                                              flags: 'gi', score: 0.9,  description: 'Datadog API Key' },
    { name: 'NEWRELIC_KEY',        pattern: 'NRAK-[A-Z0-9]{27}',                                                                                           flags: 'g',  score: 0.95, description: 'New Relic API Key' },
    { name: 'POSTMAN_KEY',         pattern: 'PMAK-[a-f0-9]{24}-[a-f0-9]{34}',                                                                              flags: 'g',  score: 0.99, description: 'Postman API Key' },
    { name: 'DISCORD_BOT_TOKEN',   pattern: '[MNO][A-Za-z0-9_\\-]{23}\\.[A-Za-z0-9_\\-]{6}\\.[A-Za-z0-9_\\-]{27,}',                                       flags: 'g',  score: 0.9,  description: 'Discord Bot Token' },
    { name: 'TELEGRAM_BOT_TOKEN',  pattern: '\\d{8,10}:AA[A-Za-z0-9_\\-]{32,}',                                                                            flags: 'g',  score: 0.95, description: 'Telegram Bot Token' },

    // ── Passwords & Secrets ──────────────────────────────────────────────
    { name: 'PASSWORD',            pattern: '(?:password|passwd|pwd)\\s*[=:]\\s*[\'"]([^\'"]{6,})[\'"]',                                                   flags: 'gi', score: 0.8,  description: 'Hardcoded Password' },
    { name: 'SECRET',              pattern: '(?:jwt[_-]?secret|secret_key|app_secret|session_secret|secret)\\s*[=:]\\s*[\'"]([^\'"]{4,})[\'"]',           flags: 'gi', score: 0.75, description: 'Hardcoded Secret' },
    { name: 'CLIENT_SECRET',       pattern: '(?:client[_-]?secret|consumer[_-]?secret)\\s*[=:]\\s*[\'"]([^\'"]{8,})[\'"]',                                flags: 'gi', score: 0.85, description: 'OAuth Client Secret' },
    { name: 'PRIVATE_TOKEN',       pattern: '(?:private[_-]?token|auth[_-]?token)\\s*[=:]\\s*[\'"]([A-Za-z0-9\\-._~+\\/]{16,})[\'"]',                     flags: 'gi', score: 0.8,  description: 'Private / Auth Token' },
    { name: 'ENCRYPTION_KEY',      pattern: '(?:encryption[_-]?key|aes[_-]?key|hmac[_-]?secret)\\s*[=:]\\s*[\'"]?([A-Za-z0-9+\\/=]{16,})[\'"]?',         flags: 'gi', score: 0.85, description: 'Encryption Key' },

    // ── Tokens ───────────────────────────────────────────────────────────
    { name: 'JWT_TOKEN',           pattern: 'eyJ[A-Za-z0-9\\-_]+\\.eyJ[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_.+\\/=]+',                                        flags: 'g',  score: 0.95, description: 'JWT Token' },
    { name: 'BEARER_TOKEN',        pattern: 'bearer\\s+([A-Za-z0-9\\-_.~+\\/]{20,})',                                                                      flags: 'gi', score: 0.85, description: 'Bearer Token' },
    { name: 'OAUTH_TOKEN',         pattern: '(?:access[_-]?token|oauth[_-]?token)\\s*[=:]\\s*[\'"]?([A-Za-z0-9\\-_.~+\\/]{20,})[\'"]?',                   flags: 'gi', score: 0.8,  description: 'OAuth Access Token' },
    { name: 'REFRESH_TOKEN',       pattern: 'refresh[_-]?token\\s*[=:]\\s*[\'"]?([A-Za-z0-9\\-_.~+\\/]{20,})[\'"]?',                                      flags: 'gi', score: 0.8,  description: 'Refresh Token' },

    // ── Database & Connection Strings ─────────────────────────────────────
    { name: 'DB_PASSWORD',         pattern: '(?:db[_-]?password|database[_-]?password)\\s*[=:]\\s*[\'"]([^\'"]{4,})[\'"]',                                 flags: 'gi', score: 0.85, description: 'Database Password' },
    { name: 'CONNECTION_STRING',   pattern: '(?:mongodb(?:\\+srv)?|postgresql|postgres|mysql|redis|amqp|mssql):\\/\\/[^\\s\'"@]*:[^\\s\'"@]+@[^\\s\'"]+',  flags: 'gi', score: 0.95, description: 'Database Connection String' },
    { name: 'DSN',                 pattern: '(?:dsn|data[_-]?source[_-]?name)\\s*[=:]\\s*[\'"]([^\'"]+)[\'"]',                                             flags: 'gi', score: 0.8,  description: 'DSN / Data Source Name' },

    // ── Private Keys & Certificates ──────────────────────────────────────
    { name: 'RSA_PRIVATE_KEY',     pattern: '-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----[\\s\\S]+?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----', flags: 'g', score: 0.99, description: 'Private Key (PEM)' },
    // NOTE: SSH *public* keys (ssh-rsa AAAA…) were intentionally removed — a public key is not a
    // secret, and flagging it as a CRITICAL secret produced false positives on *.pub / authorized_keys.
    { name: 'WEBHOOK_URL',         pattern: 'https:\\/\\/(?:hooks\\.slack\\.com|discord\\.com\\/api\\/webhooks|discordapp\\.com\\/api\\/webhooks)\\/[^\\s\'"]+', flags: 'g', score: 0.95, description: 'Webhook URL (Slack/Discord)' },
];
