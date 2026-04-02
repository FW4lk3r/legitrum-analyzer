<?php

namespace Legitrum\Analyzer\Tests\Integration;

use Legitrum\Analyzer\Auth\LegitruAuthClient;
use PHPUnit\Framework\TestCase;

/**
 * Integration tests verifying server-side validation behavior.
 *
 * These tests require a running Legitrum server. They are skipped
 * automatically if the server is not reachable.
 *
 * Run with: LEGITRUM_TEST_SERVER=http://host.docker.internal:8000 LEGITRUM_TEST_TOKEN=xxx phpunit tests/Integration/
 *
 * @group integration
 */
class ServerSideValidationTest extends TestCase
{
    private ?LegitruAuthClient $client = null;

    private string $server;

    protected function setUp(): void
    {
        $this->server = getenv('LEGITRUM_TEST_SERVER') ?: '';
        $token = getenv('LEGITRUM_TEST_TOKEN') ?: '';

        if (empty($this->server) || empty($token)) {
            $this->markTestSkipped('LEGITRUM_TEST_SERVER and LEGITRUM_TEST_TOKEN must be set for integration tests');
        }

        $this->client = new LegitruAuthClient($token, $this->server);
    }

    public function testAuthenticateRejectsNonExistentAssessment(): void
    {
        $this->expectException(\RuntimeException::class);

        // Assessment ID 999999999 should not exist
        $this->client->authenticate(999999999);
    }

    public function testAuthenticateRejectsZeroAssessmentId(): void
    {
        $this->expectException(\RuntimeException::class);

        $this->client->authenticate(0);
    }

    public function testAuthenticateRejectsNegativeAssessmentId(): void
    {
        $this->expectException(\RuntimeException::class);

        $this->client->authenticate(-1);
    }

    public function testInvalidTokenIsRejected(): void
    {
        $badClient = new LegitruAuthClient('invalid-token-that-does-not-exist', $this->server);

        $this->expectException(\RuntimeException::class);

        $badClient->authenticate(1);
    }

    public function testGetCriteriaRejectsUnauthenticatedAssessment(): void
    {
        // Attempt to fetch criteria without authenticating first
        $this->expectException(\Exception::class);

        $this->client->getCriteria(999999999);
    }

    public function testReportEvidenceRejectsInvalidCriterion(): void
    {
        // Submit evidence for a criterion that doesn't exist
        $result = $this->client->reportEvidence(
            999999999,
            0,
            [
                'snippets' => [],
                'files_searched' => 0,
                'files_relevant' => 0,
            ],
        );

        // Should return empty (failed after retries) or throw
        $this->assertEmpty($result);
    }

    public function testReportEvidenceHandlesEmptySnippets(): void
    {
        // Even with valid-looking IDs, unauthorized submissions should fail
        $result = $this->client->reportEvidence(
            999999999,
            999999999,
            [
                'snippets' => [],
                'files_searched' => 0,
                'files_relevant' => 0,
            ],
        );

        $this->assertEmpty($result);
    }
}
