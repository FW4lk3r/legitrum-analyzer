<?php

namespace Legitrum\Analyzer\Auth;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\GuzzleException;
use InvalidArgumentException;
use Legitrum\Analyzer\Logging\Logger;

class LegitruAuthClient
{
    /**
     * Allowed server URL patterns.
     *
     * Local entries (localhost, 127.0.0.1, host.docker.internal) exist because
     * this analyzer runs inside Docker containers that communicate with the
     * host-running Legitrum server during development/staging. HTTP is permitted
     * only for these local addresses — non-local servers must use HTTPS.
     *
     * SSRF mitigation: the analyzer is a CLI tool with no inbound HTTP surface.
     * It only calls these endpoints outbound with a bearer token. The allowlist
     * prevents a compromised LEGITRUM_SERVER env var from directing requests to
     * arbitrary internal services.
     *
     * DNS rebinding: localhost/127.0.0.1 are resolved by the container's own
     * resolver, not by external DNS, so rebinding is not a vector here.
     * host.docker.internal is resolved by Docker's built-in DNS.
     *
     * Production: migrate this to an externally-managed config store
     * (e.g., HashiCorp Vault) with read-only application access.
     */
    private const ALLOWED_SERVERS = [
        'https://localhost',
        'https://localhost:*',
        'http://localhost',
        'http://localhost:*',
        'https://127.0.0.1',
        'https://127.0.0.1:*',
        'http://127.0.0.1',
        'http://127.0.0.1:*',
        'http://host.docker.internal',
        'http://host.docker.internal:*',
        'https://host.docker.internal',
        'https://host.docker.internal:*',
        'https://*.legitrum.pt',
        'https://*.legitrum.internal',
    ];

    private Client $client;

    private Logger $logger;

    public function __construct(
        private string $token,
        private string $server,
        ?Logger $logger = null,
    ) {
        $this->logger = $logger ?? new Logger();
        $this->validateServerUrl($server);

        $isLocal = $this->isLocalServer($server);

        $this->client = new Client([
            'base_uri' => rtrim($server, '/'),
            'timeout' => 30,
            'verify' => ! $isLocal,
            'curl' => $isLocal ? [] : [
                CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2,
            ],
            'headers' => [
                'Authorization' => "Bearer {$token}",
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'User-Agent' => 'Legitrum-Analyzer/1.0',
            ],
        ]);
    }

    /**
     * Authenticate with the Legitrum server.
     *
     * Server validates: token is valid and not expired, assessment_id exists
     * and is active, and the token owner has permission to analyze it.
     * Returns assessment metadata on success (criteria count, title, etc.).
     */
    public function authenticate(int $assessmentId): array
    {
        try {
            $response = $this->client->post('/api/analyzer/authenticate', [
                'json' => ['assessment_id' => $assessmentId],
            ]);

            $data = json_decode($response->getBody()->getContents(), true);

            if (! is_array($data)) {
                $this->logger->error('Authentication response is not valid JSON', [
                    'assessment_id' => $assessmentId,
                    'raw_type' => gettype($data),
                ]);
                throw new \RuntimeException('Authentication failed: invalid response from server');
            }

            return $data;
        } catch (ClientException $e) {
            $status = $e->getResponse()->getStatusCode();
            $body = $e->getResponse()->getBody()->getContents();
            $reason = $this->extractFailureReason($status, $body);

            $this->logger->error('Authentication failed', [
                'event' => 'authentication_failed',
                'assessment_id' => $assessmentId,
                'http_status' => $status,
                'reason' => $reason,
                'server' => $this->server,
                'token_prefix' => substr($this->token, 0, 8) . '...',
            ]);

            throw new \RuntimeException("Authentication failed (HTTP {$status}): {$reason}", $status, $e);
        } catch (GuzzleException $e) {
            $this->logger->error('Authentication connection failure', [
                'event' => 'authentication_error',
                'assessment_id' => $assessmentId,
                'reason' => 'connection_failure',
                'detail' => $e->getMessage(),
                'server' => $this->server,
            ]);

            throw new \RuntimeException("Authentication failed: could not reach server — {$e->getMessage()}", 0, $e);
        }
    }

    /**
     * Fetch criteria for analysis.
     *
     * Server validates: assessment is authenticated in current session,
     * returns criteria with search_patterns for each. Returns 404 if
     * assessment doesn't exist, 403 if not authorized.
     */
    public function getCriteria(int $assessmentId): array
    {
        try {
            $response = $this->client->get("/api/analyzer/criteria/{$assessmentId}");
        } catch (ClientException $e) {
            $status = $e->getResponse()->getStatusCode();
            $reason = $this->extractFailureReason($status, $e->getResponse()->getBody()->getContents());

            $this->logger->error('Authorization denied for criteria fetch', [
                'event' => 'criteria_auth_rejected',
                'assessment_id' => $assessmentId,
                'http_status' => $status,
                'reason' => $reason,
            ]);

            throw new \RuntimeException("Failed to fetch criteria (HTTP {$status}): {$reason}", $status, $e);
        }

        $data = json_decode($response->getBody()->getContents(), true);

        if (! is_array($data)) {
            $this->logger->error('Criteria response is not valid JSON', [
                'assessment_id' => $assessmentId,
            ]);
            throw new \RuntimeException('Failed to fetch criteria: invalid response from server');
        }

        return $data;
    }

    /**
     * Send evidence for a criterion, chunked if needed.
     *
     * Server validates: assessment is authenticated, criterion_id belongs to
     * the assessment, payload is well-formed, enforces rate limits, and
     * persists only authorized submissions.
     */
    public function reportEvidence(
        int $assessmentId,
        int $criterionId,
        array $data,
        int $chunkIndex = 0,
        int $chunksTotal = 1,
    ): array {
        $payload = [
            'assessment_id'  => $assessmentId,
            'criterion_id'   => $criterionId,
            'snippets'       => $data['snippets'] ?? [],
            'chunk_index'    => $chunkIndex,
            'chunks_total'   => $chunksTotal,
            'files_searched' => $data['files_searched'] ?? 0,
            'files_relevant' => $data['files_relevant'] ?? 0,
        ];

        $maxRetries = 3;
        $attempt    = 0;

        while ($attempt < $maxRetries) {
            try {
                $response = $this->client->post('/api/analyzer/evidence', [
                    'json' => $payload,
                ]);
                return json_decode($response->getBody()->getContents(), true);
            } catch (ClientException $e) {
                $status = $e->getResponse()->getStatusCode();
                if ($status === 401 || $status === 403) {
                    $this->logger->error('Evidence submission auth rejected', [
                        'event' => 'evidence_auth_rejected',
                        'assessment_id' => $assessmentId,
                        'criterion_id' => $criterionId,
                        'http_status' => $status,
                        'chunk' => "{$chunkIndex}/{$chunksTotal}",
                    ]);
                }
                $attempt++;
                if ($attempt >= $maxRetries) {
                    $this->logger->warn('Failed to send evidence chunk', [
                        'criterion_id' => $criterionId,
                        'chunk' => $chunkIndex,
                        'attempts' => $maxRetries,
                        'error' => $e->getMessage(),
                    ]);
                    return [];
                }
                sleep(2 * $attempt);
            } catch (\Exception $e) {
                $attempt++;
                if ($attempt >= $maxRetries) {
                    $this->logger->warn('Failed to send evidence chunk', [
                        'criterion_id' => $criterionId,
                        'chunk' => $chunkIndex,
                        'attempts' => $maxRetries,
                        'error' => $e->getMessage(),
                    ]);
                    return [];
                }
                sleep(2 * $attempt);
            }
        }
        return [];
    }

    public function reportProgress(int $assessmentId, array $data): void
    {
        try {
            $this->client->post("/api/analyzer/status/{$assessmentId}", [
                'json' => $data,
            ]);
        } catch (GuzzleException $e) {
            $this->logger->debug('Progress report failed (non-critical)', [
                'assessment_id' => $assessmentId,
                'error' => $e->getMessage(),
            ]);
        }
    }

    public function reportSbomFiles(int $assessmentId, array $files): void
    {
        try {
            $this->client->post('/api/analyzer/sbom', [
                'json' => [
                    'assessment_id' => $assessmentId,
                    'files'         => $files,
                ],
            ]);
        } catch (\Exception $e) {
            $this->logger->warn('Failed to send SBOM files', [
                'assessment_id' => $assessmentId,
                'error' => $e->getMessage(),
            ]);
        }
    }

    public function reportComplete(int $assessmentId, array $summary): void
    {
        $maxRetries = 3;
        $attempt    = 0;

        while ($attempt < $maxRetries) {
            try {
                $this->client->post('/api/analyzer/complete', [
                    'json' => [
                        'assessment_id' => $assessmentId,
                        'summary'       => $summary,
                    ],
                ]);
                return;
            } catch (\Exception $e) {
                $attempt++;
                if ($attempt >= $maxRetries) {
                    $this->logger->warn('Failed to report completion', [
                        'assessment_id' => $assessmentId,
                        'attempts' => $maxRetries,
                        'error' => $e->getMessage(),
                    ]);
                    return;
                }
                sleep(2);
            }
        }
    }

    private function validateServerUrl(string $server): void
    {
        $parsed = parse_url($server);
        if (! $parsed || ! isset($parsed['scheme']) || ! isset($parsed['host'])) {
            throw new InvalidArgumentException('Invalid server URL format');
        }

        if (! in_array($parsed['scheme'], ['http', 'https'], true)) {
            throw new InvalidArgumentException("Invalid URL scheme: {$parsed['scheme']}");
        }

        if (! $this->isAllowedServer($server)) {
            $this->logger->error('Server URL rejected by allowlist', [
                'event' => 'url_validation_rejected',
                'server' => $server,
                'host' => $parsed['host'],
                'scheme' => $parsed['scheme'],
            ]);
            throw new InvalidArgumentException("Server not in allowlist: {$server}");
        }

        $this->logger->info('Server URL validated', [
            'event' => 'url_validation_passed',
            'host' => $parsed['host'],
            'scheme' => $parsed['scheme'],
            'is_local' => $this->isLocalServer($server),
        ]);

        if ($parsed['scheme'] === 'http' && ! $this->isLocalServer($server)) {
            $this->logger->warn('Using unencrypted HTTP for non-local server', [
                'host' => $parsed['host'],
            ]);
        }
    }

    private function isLocalServer(string $server): bool
    {
        $parsed = parse_url($server);
        $host = $parsed['host'] ?? '';

        return in_array($host, ['localhost', '127.0.0.1', 'host.docker.internal'], true);
    }

    private function isAllowedServer(string $server): bool
    {
        $normalized = rtrim($server, '/');

        foreach (self::ALLOWED_SERVERS as $allowed) {
            if (fnmatch($allowed, $normalized)) {
                return true;
            }
        }

        return false;
    }

    private function extractFailureReason(int $status, string $body): string
    {
        return match ($status) {
            401 => 'invalid_or_expired_token',
            403 => 'access_denied',
            404 => 'endpoint_not_found',
            422 => 'validation_error',
            429 => 'rate_limited',
            default => "http_error_{$status}",
        };
    }
}
