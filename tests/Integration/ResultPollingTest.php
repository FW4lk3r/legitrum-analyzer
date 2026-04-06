<?php

namespace Legitrum\Analyzer\Tests\Integration;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Legitrum\Analyzer\Auth\LegitruAuthClient;
use Legitrum\Analyzer\Logging\Logger;
use PHPUnit\Framework\TestCase;

class ResultPollingTest extends TestCase
{
    private function createLogger(): array
    {
        $stdout = fopen('php://memory', 'rw');
        $stderr = fopen('php://memory', 'rw');
        $logger = new Logger('debug', 'legitrum-analyzer', 'development', $stdout, $stderr);

        return [$logger, $stdout, $stderr];
    }

    private function readStream($stream): string
    {
        rewind($stream);

        return stream_get_contents($stream);
    }

    private function createClientWithMock(MockHandler $mock, Logger $logger): LegitruAuthClient
    {
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        // Use reflection to inject the mock Guzzle client
        $authClient = new LegitruAuthClient('test-token', 'https://localhost', $logger);
        $reflection = new \ReflectionClass($authClient);
        $prop = $reflection->getProperty('client');
        $prop->setAccessible(true);
        $prop->setValue($authClient, $client);

        return $authClient;
    }

    public function testGetResultsReturnsCompletedResults(): void
    {
        [$logger] = $this->createLogger();

        $body = json_encode([
            'status' => 'completed',
            'results' => [
                'overall_score' => 85,
                'overall_status' => 'compliant',
                'criteria' => [],
            ],
        ]);

        $mock = new MockHandler([new Response(200, [], $body)]);
        $client = $this->createClientWithMock($mock, $logger);

        $result = $client->getResults(123);

        $this->assertNotNull($result);
        $this->assertSame('completed', $result['status']);
        $this->assertSame(85, $result['results']['overall_score']);
    }

    public function testGetResultsReturnsProcessingStatus(): void
    {
        [$logger] = $this->createLogger();

        $body = json_encode(['status' => 'processing']);
        $mock = new MockHandler([new Response(200, [], $body)]);
        $client = $this->createClientWithMock($mock, $logger);

        $result = $client->getResults(123);

        $this->assertNotNull($result);
        $this->assertSame('processing', $result['status']);
    }

    public function testGetResultsReturnsFailedStatus(): void
    {
        [$logger] = $this->createLogger();

        $body = json_encode(['status' => 'failed', 'reason' => 'model_error']);
        $mock = new MockHandler([new Response(200, [], $body)]);
        $client = $this->createClientWithMock($mock, $logger);

        $result = $client->getResults(123);

        $this->assertNotNull($result);
        $this->assertSame('failed', $result['status']);
    }

    public function testGetResultsReturnsNullOn404(): void
    {
        [$logger, , $stderr] = $this->createLogger();

        $mock = new MockHandler([new Response(404, [], '{"error": "not found"}')]);
        $client = $this->createClientWithMock($mock, $logger);

        $result = $client->getResults(123);

        $this->assertNull($result);
        $this->assertStringContainsString('results_endpoint_not_found', $this->readStream($stderr));
    }

    public function testGetResultsHandles429WithRetryAfter(): void
    {
        [$logger, , $stderr] = $this->createLogger();

        $mock = new MockHandler([
            new Response(429, ['Retry-After' => '30'], '{"error": "rate limited"}'),
        ]);
        $client = $this->createClientWithMock($mock, $logger);

        $result = $client->getResults(123);

        $this->assertNotNull($result);
        $this->assertSame('processing', $result['status']);
        $this->assertSame(30, $result['_retry_after']);
        $this->assertStringContainsString('results_rate_limited', $this->readStream($stderr));
    }

    public function testGetResultsHandles401AsAuthError(): void
    {
        [$logger, , $stderr] = $this->createLogger();

        $mock = new MockHandler([new Response(401, [], '{"error": "unauthenticated"}')]);
        $client = $this->createClientWithMock($mock, $logger);

        $result = $client->getResults(123);

        $this->assertNotNull($result);
        $this->assertSame('failed', $result['status']);
        $this->assertSame('authentication_error', $result['reason']);
        $this->assertStringContainsString('results_auth_rejected', $this->readStream($stderr));
    }

    public function testGetResultsHandles5xxAsContinuePolling(): void
    {
        [$logger, , $stderr] = $this->createLogger();

        $mock = new MockHandler([new Response(500, [], '{"error": "internal"}')]);
        $client = $this->createClientWithMock($mock, $logger);

        $result = $client->getResults(123);

        $this->assertNotNull($result);
        $this->assertSame('processing', $result['status']);
        $this->assertStringContainsString('results_fetch_error', $this->readStream($stderr));
    }
}
