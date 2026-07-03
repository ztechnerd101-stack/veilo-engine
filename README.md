# veilo-engine

The detection engine that powers the [Veilo VS Code extension](https://marketplace.visualstudio.com/items?itemName=veilo.veilo) — the regex rules, validators, and scanner that find secrets, credentials, PII, and security issues in source code.

It's published so you can **read exactly what Veilo looks for and how it decides**. No detection logic is hidden.

## What this repo is

- **`src/core/`** — the pure, dependency-free scanner: pattern definitions (`patterns/secrets.ts`, `patterns/pii.ts`, `patterns/security.ts`), validators, entropy scoring, ignore/baseline handling, and the `scan()` entry points. No editor or platform dependencies.
- **`src/detectors/`** — thin adapters that wrap the core scanner for the VS Code extension.

Everything here runs locally. The engine takes text in and returns findings out — it makes no network calls of its own.

## What this repo is *not*

This is **not** the full Veilo extension. It deliberately excludes:

- Licensing / activation (Ed25519 key validation, the license server)
- The VS Code UI, diagnostics, and status bar
- The git pre-commit hook installer and redaction flow
- Quick-Fix code actions
- The Team/Gumroad billing backend

Those stay in the closed-source extension. This repo is the detection core only.

## What's actually verifiable here

`core/` is the real engine — pattern matchers, entropy analysis, Luhn/mod-97 checksum
validation. It has no VS Code dependency. Clone it, read it, run it.

`detectors/` is the thin VS Code integration layer that wires core/ into the editor
(diagnostics, quick-fixes). It imports the `vscode` API and won't compile standalone —
it's here so you can see how the wiring works, not as something you'd run on its own.

If you only trust one directory to actually check the "100% local" claim, check core/.

## Rule IDs

Security rules are identified as `VEILO-001` … `VEILO-025`, each mapped to a CWE.

## Get Veilo

- **Install:** [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=veilo.veilo)
- **Pro (individual, $30 one-time):** https://zeinsaleh.gumroad.com/l/cldizw
- **Team (5/10/25 seats):** https://veilo-ext.fly.dev/team

Secret & credential detection is free. Pro unlocks PII detection, the 25 security rules, Quick-Fix, and commit protection.

## Credibility

<!-- TODO(zein): link the 10-bug-fix writeup here as a changelog / credibility story once it's published.
     Replace this with the real URL (e.g. a CHANGELOG.md in this repo or a blog/gist link). -->
Veilo's detectors are tuned against real false-positive reports. A writeup of 10 detection bugs found and fixed is tracked as a changelog — _link TODO_.

## License

MIT — see [LICENSE](LICENSE).
