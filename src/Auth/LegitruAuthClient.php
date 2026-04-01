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
            'json' => ['token' => $this->token],
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
        $response = $this->client->post('/api/analyzer/evidence', [
            'json' => [
                'assessment_id' => $assessmentId,
                'criterion_id' => $criterionId,
                'snippets' => $data['snippets'] ?? [],
                'chunk_index' => $chunkIndex,
                'chunks_total' => $chunksTotal,
                'files_searched' => $data['files_searched'] ?? 0,
                'files_relevant' => $data['files_relevant'] ?? 0,
            ],
        ]);

        return json_decode($response->getBody()->getContents(), true);
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
        $this->client->post('/api/analyzer/evidence', [
            'json' => [
                'assessment_id' => $assessmentId,
                'criterion_id' => 0,
                'snippets' => [],
                'chunk_index' => 0,
                'chunks_total' => 1,
                'files_searched' => 0,
                'files_relevant' => 0,
                'status' => 'analyzer_complete',
                'summary' => $summary,
            ],
        ]);
    }
}
