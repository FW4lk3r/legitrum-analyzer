<?php

namespace Legitrum\Analyzer\Auth;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

class LegitruAuthClient
{
    private Client $client;

    public function __construct(
        private string $token,
        private string $server,
    ) {
        $this->client = new Client([
            'base_uri' => rtrim($server, '/'),
            'timeout' => 30,
            'headers' => [
                'Authorization' => "Bearer {$token}",
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'User-Agent' => 'Legitrum-Analyzer/1.0',
            ],
        ]);
    }

    public function authenticate(int $assessmentId): array
    {
        $response = $this->client->post('/api/analyzer/authenticate', [
            'json' => ['assessment_id' => $assessmentId],
            // token already in Authorization header
        ]);

        return json_decode($response->getBody()->getContents(), true);
    }

    public function getCriteria(int $assessmentId): array
    {
        $response = $this->client->get("/api/analyzer/criteria/{$assessmentId}");

        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * Send evidence for a criterion, chunked if needed.
     *
     * @param  array  $snippets  Full array of snippets for this criterion
     * @param  int    $chunkIndex  0-based chunk index
     * @param  int    $chunksTotal  Total number of chunks for this criterion
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
            } catch (\Exception $e) {
                $attempt++;
                if ($attempt >= $maxRetries) {
                    // Log but don't crash — continue with next criterion
                    fwrite(STDERR, "WARNING: Failed to send chunk {$chunkIndex} for criterion {$criterionId} after {$maxRetries} attempts: {$e->getMessage()}\n");
                    return [];
                }
                sleep(2 * $attempt); // exponential backoff: 2s, 4s, 6s
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
            // Non-critical — continue analysis
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
                    fwrite(STDERR, "WARNING: Failed to report completion: {$e->getMessage()}\n");
                    return;
                }
                sleep(2);
            }
        }
    }
}
