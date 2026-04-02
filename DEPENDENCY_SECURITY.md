# Dependency Security Policy

## Audit Process

All dependencies are audited for known vulnerabilities before merge and on a recurring schedule.

### Tools

| Tool | Purpose | Command |
|------|---------|---------|
| `composer audit` | PHP dependency vulnerability scanning | `composer audit` |
| CycloneDX PHP Composer | SBOM generation (CycloneDX 1.5 format) | `composer sbom` |

### How to Run Locally

```bash
# Inside Docker container
docker compose run --rm analyzer composer audit

# Generate SBOM
docker compose run --rm analyzer composer install && docker compose run --rm analyzer composer sbom
```

## CI/CD Integration

GitHub Actions workflow: `.github/workflows/dependency-audit.yml`

- **On PR**: Runs `composer audit` — blocks merge on high/critical vulnerabilities
- **On push to master**: Runs audit + generates SBOM artifact
- **Weekly (Monday 08:00 UTC)**: Scheduled audit to catch newly disclosed CVEs

## Scan Frequency

| Trigger | Frequency |
|---------|-----------|
| PR with dependency changes | Every PR |
| Master push | Every merge |
| Scheduled scan | Weekly |

## Remediation SLAs

| Severity | SLA |
|----------|-----|
| Critical | 24 hours |
| High | 72 hours |
| Medium | 2 weeks |
| Low | Next release cycle |

## Risk Acceptances

If a vulnerability cannot be patched (no fix available, false positive, not applicable to our usage), document it here:

| Dependency | CVE | Severity | Justification | Accepted By | Date |
|------------|-----|----------|---------------|-------------|------|
| *(none currently)* | — | — | — | — | — |

## FileIndexer Note

The `FileIndexer` in `src/Scanner/FileIndexer.php` excludes lock files (`composer.lock`, `package-lock.json`, etc.) from code analysis scanning. This does **not** affect dependency auditing — `composer audit` and SBOM generation read these files independently via Composer's own mechanisms.

## Current Dependencies

### Production
- `guzzlehttp/guzzle` ^7.8 — HTTP client for Legitrum API communication

### Development
- `phpunit/phpunit` ^10.5 — Unit testing
- `cyclonedx/cyclonedx-php-composer` ^5.0 — SBOM generation
