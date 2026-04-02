# Patch Management Policy

## Scope

This policy applies to all third-party dependencies in the Legitrum Analyzer project, managed via Composer.

## Vulnerability Response SLAs

| CVSS Score | Severity | SLA | Action |
|-----------|----------|-----|--------|
| 9.0 – 10.0 | Critical | 7 days | Patch immediately, hotfix release |
| 7.0 – 8.9 | High | 14 days | Patch in next sprint |
| 4.0 – 6.9 | Medium | 30 days | Schedule for next release |
| 0.1 – 3.9 | Low | 90 days | Best effort |

SLA starts from the date the vulnerability is detected (Dependabot alert or CI audit failure).

## Detection

| Method | Frequency | Trigger |
|--------|-----------|---------|
| `composer audit` (CI) | Every push to master | Automatic |
| `composer audit` (CI) | Every PR touching composer.json/lock | Automatic |
| `composer audit` (CI) | Weekly (Monday 08:00 UTC) | Scheduled |
| Dependabot | Weekly (Monday) | Automatic PRs |
| Monthly compliance audit | Monthly (1st) | Scheduled workflow |

## Roles

| Role | Responsibility |
|------|---------------|
| **PR Author** (Dependabot or developer) | Create update PR |
| **Reviewer** | Verify update doesn't break functionality, check changelog for breaking changes |
| **Maintainer** | Merge PR, monitor post-merge for issues |

## Testing Requirements

Before merging a dependency update:

1. CI pipeline passes (composer audit + build)
2. PHPUnit test suite passes
3. Docker image builds successfully
4. For major version bumps: manual smoke test in staging

## Dependabot Configuration

- Composer dependencies: weekly, Monday
- GitHub Actions: weekly
- Auto-labels: `dependencies`, `security`
- Max open PRs: 10

## Risk Acceptance

If a vulnerability cannot be patched:

1. Document in `DEPENDENCY_SECURITY.md` (Risk Acceptances table)
2. Include: CVE, severity, justification, accepted by, date
3. Set a review date (max 90 days)
4. Re-evaluate when a patch becomes available

## Evidence Collection

- CI audit results: stored as GitHub Actions artifacts (30-day retention)
- SBOM: generated on each master push (90-day retention)
- Monthly audit export: `compliance/patch_audit_log.csv`

## Current Status

### Workflow Runs (last 5)

| Date | Status | Trigger | Commit |
|------|--------|---------|--------|
| 2026-04-02 | Pass | push (master) | Document both usage methods in README |
| 2026-04-02 | Pass | PR | deps: cyclonedx ^5.0 to ^6.2 |
| 2026-04-02 | Pass | push (master) | Allow cyclonedx composer plugin |
| 2026-04-02 | Pass | PR | deps: cyclonedx ^5.0 to ^6.2 |
| 2026-04-02 | Fail | push (master) | Make .env.secrets optional |

### Open Dependabot PRs

| PR | Title | Created |
|----|-------|---------|
| #3 | deps: update cyclonedx/cyclonedx-php-composer ^5.0 to ^6.2 | 2026-04-02 |
| #2 | Bump actions/upload-artifact from 4 to 7 | 2026-04-02 |
| #1 | Bump actions/checkout from 4 to 6 | 2026-04-02 |
