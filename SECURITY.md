# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability, **do not open a public issue**.

1. Email: security@legitrum.pt
2. Include: description, reproduction steps, affected version, and impact assessment
3. You will receive an acknowledgement within **48 hours**
4. We will provide a fix timeline within **5 business days**
5. Once patched, we will credit you in the release notes (unless you prefer anonymity)

Please allow us to address the issue before public disclosure. We follow a **90-day coordinated disclosure** timeline.

## Severity Classification

| Level | CVSS | Description | Example |
|-------|------|-------------|---------|
| **CRITICAL** | 9.0 – 10.0 | Remote code execution, credential exposure, data exfiltration | Token leaked in logs, arbitrary file read via path traversal |
| **HIGH** | 7.0 – 8.9 | Authentication bypass, significant data exposure | Server allowlist bypass, SBOM data sent to unauthorized endpoint |
| **MEDIUM** | 4.0 – 6.9 | Limited information disclosure, denial of service | Excessive memory usage from large patterns, unvalidated file types |
| **LOW** | 0.1 – 3.9 | Minor information leak, best-practice deviation | Verbose error messages in development mode, missing security headers |

## Remediation Timeline

| Severity | Response Time | Fix Deployed | Notification |
|----------|--------------|-------------|-------------|
| CRITICAL | 24 hours | 48 hours | Immediate to all users |
| HIGH | 72 hours | 7 days | Release notes + email |
| MEDIUM | 7 days | 14 days | Release notes |
| LOW | 14 days | Next release | Changelog |

## Discovery Process

Vulnerabilities are identified through:

### Automated Scanning
- **Dependabot** (`.github/dependabot.yml`) — weekly dependency updates for Composer and GitHub Actions
- **Composer Audit** (`.github/workflows/dependency-audit.yml`) — runs on every PR, every push to master, and weekly scheduled scan
- **Monthly Compliance Audit** (`.github/workflows/monthly-audit.yml`) — exports audit trail to `compliance/patch_audit_log.csv`

### Code-Level Defenses
- **FileValidator** — magic byte verification, polyglot detection, entropy analysis
- **GrepSearch** — path traversal prevention, base directory whitelist, pattern sanitization
- **Logger** — automatic PII/credential redaction (SENSITIVE_KEYS)
- **LegitruAuthClient** — URL allowlist, TLS 1.2 enforcement, structured auth failure logging

### Code Review
- All PRs require review before merge
- Security-labeled PRs receive priority review

## Escalation Procedures

1. **Detection** — automated scan or manual report
2. **Triage** — maintainer assesses severity within response time SLA
3. **Fix** — develop patch in a private branch
4. **Review** — security-focused code review required for CRITICAL/HIGH
5. **Release** — deploy fix, publish advisory
6. **Disclosure** — notify reporter, update changelog

For CRITICAL vulnerabilities:
- Maintainer is notified immediately via email
- Fix is deployed as hotfix release (bypasses normal release cycle)
- All users notified within 24 hours of fix

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x (latest) | Yes |
| < 1.0 | No |

Only the latest release receives security patches. Users should always run the latest Docker image.

## Current Security Tools

| Tool | Config | Purpose |
|------|--------|---------|
| Dependabot | `.github/dependabot.yml` | Automated dependency update PRs |
| Composer Audit | `.github/workflows/dependency-audit.yml` | Vulnerability scanning on CI |
| Monthly Audit | `.github/workflows/monthly-audit.yml` | Compliance evidence export |
| CycloneDX | `composer sbom` | SBOM generation |

---

## Input Validation Strategy

### Path Validation

All file paths are validated before access:

1. **Base directory whitelist** — `GrepSearch` only accepts project paths under `/repo` (Docker mount) or `/tmp` (testing). Paths outside these directories are rejected with `InvalidArgumentException`.
2. **Path traversal prevention** — Every file path is resolved via `realpath()` and verified to be under the project root. Paths containing `../` that resolve outside the project are silently skipped.
3. **Symlink protection** — Symlinks that resolve outside the project directory are rejected (the `realpath()` check catches these).

### Pattern Validation

Search patterns received from the Legitrum API are sanitized before use:

- **Empty/blank patterns** are dropped
- **Non-string values** are dropped
- **Oversized patterns** (>1000 characters) are dropped — prevents memory abuse in string matching operations

### File Content Validation (FileValidator)

When `ENABLE_STRICT_VALIDATION=true` (default), files are validated before reading:

- **Magic byte verification** — File headers are checked against expected signatures for their extension
- **Polyglot/binary detection** — Files starting with ZIP, ELF, PE, PNG, JPEG, PDF, or GZIP headers are rejected
- **Entropy analysis** — Files with Shannon entropy > 6.5 (in the first 4KB) trigger a warning

### CLI Input Validation

- `LEGITRUM_TOKEN` — Must be non-empty
- `ASSESSMENT_ID` — Must be numeric
- `LOG_LEVEL` — Must be `info` or `debug`
- `LEGITRUM_SERVER` — Must match the URL allowlist with `http` or `https` scheme
- `/repo` path — Must exist and resolve to itself (no symlink tricks)

## Credential Handling

- Tokens are never logged in full — only the first 8 characters appear in error logs
- The structured logger automatically redacts values for keys containing: `password`, `token`, `secret`, `authorization`, `cookie`, `api_key`, `credential`, `private_key`, `ssn`, `credit_card`, `cvv`, `national_id`, `passport`, `bank_account`, `health_data`, `medical`
- Secrets are loaded from environment variables via `secrets/config.php`, never hardcoded
- Production mode (`APP_ENV=production`) suppresses stack traces and enforces minimum `info` log level
