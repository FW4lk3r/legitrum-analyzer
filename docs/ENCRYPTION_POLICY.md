# Encryption Policy

## Network Connections

This application has a single network client: the Guzzle HTTP client in `src/Auth/LegitruAuthClient.php`.

There are no database connections, Redis/cache clients, gRPC stubs, or message queues.

### TLS Requirements

| Server Type | TLS Version | Certificate Verification | Rationale |
|-------------|-------------|-------------------------|-----------|
| Production (`*.legitrum.pt`) | >= TLS 1.2 | Enabled | Full encryption and identity verification |
| Internal (`*.legitrum.internal`) | >= TLS 1.2 | Enabled | Internal traffic still encrypted |
| Local (`localhost`, `127.0.0.1`) | Not enforced | Disabled | No certs available in local dev containers |
| Docker (`host.docker.internal`) | Not enforced | Disabled | Docker bridge network, no TLS termination |

### Implementation Details

```php
// Non-local: TLS 1.2+ with certificate verification
'verify' => true,
'curl' => [CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2]

// Local: plain HTTP allowed, no verification
'verify' => false,
'curl' => []
```

### Why Local Servers Disable SSL

- The analyzer runs inside a Docker container communicating with a host-running dev server
- Docker containers don't have access to the host's certificate store
- The host dev server (Laravel `php artisan serve`) doesn't run HTTPS
- Traffic stays within the Docker bridge network — not routed externally
- The URL allowlist prevents this exception from being exploited against non-local targets

### Cipher Suites

Cipher suite selection is delegated to the system's OpenSSL/libcurl configuration. The Docker base image (`php:8.2-cli-alpine`) ships with a current OpenSSL that defaults to strong cipher suites and disables known-weak algorithms (RC4, DES, export ciphers).

Custom cipher pinning is not implemented because:
- Alpine's OpenSSL defaults are already secure
- Custom cipher lists create maintenance burden and break when servers update
- TLS 1.2 minimum already excludes all weak cipher suites

## Exceptions Process

To add a new server or relax encryption for a connection:

1. Add the URL pattern to `ALLOWED_SERVERS` in `LegitruAuthClient.php`
2. Document the justification in this file
3. If HTTP (not HTTPS), it must be a local address — non-local HTTP is logged as a warning
4. Add a test in `tests/Security/EncryptionComplianceTest.php`

## Audit Schedule

| Check | Frequency | Tool |
|-------|-----------|------|
| Dependency vulnerabilities | Weekly + every PR | `composer audit` (CI) |
| TLS configuration compliance | Every release | `EncryptionComplianceTest.php` |
| Network client inventory | Quarterly | `grep -r 'new Client\|curl_init\|new PDO' src/` |
