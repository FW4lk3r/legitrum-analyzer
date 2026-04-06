<?php

namespace Legitrum\Analyzer\Tests\Notifier;

use Legitrum\Analyzer\Auth\LegitruAuthClient;
use Legitrum\Analyzer\Logging\Logger;
use Legitrum\Analyzer\Notifier\WebhookNotifier;
use PHPUnit\Framework\TestCase;

class WebhookNotifierTest extends TestCase
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

    private function createMockAuthClient(bool $isAllowed): LegitruAuthClient
    {
        $mock = $this->createMock(LegitruAuthClient::class);
        $mock->method('isAllowedServer')->willReturn($isAllowed);

        return $mock;
    }

    public function testRejectsUrlNotInAllowlist(): void
    {
        [$logger, , $stderr] = $this->createLogger();
        $authClient = $this->createMockAuthClient(false);
        $notifier = new WebhookNotifier($logger, $authClient);

        $notifier->send('https://evil.com/webhook', ['test' => true]);

        $output = $this->readStream($stderr);
        $this->assertStringContainsString('webhook_url_not_allowed', $output);
    }

    public function testRejectsInvalidUrl(): void
    {
        [$logger, , $stderr] = $this->createLogger();
        $authClient = $this->createMockAuthClient(true);
        $notifier = new WebhookNotifier($logger, $authClient);

        $notifier->send('not-a-url', ['test' => true]);

        $output = $this->readStream($stderr);
        $this->assertStringContainsString('webhook_url_invalid', $output);
    }

    public function testRejectsInvalidScheme(): void
    {
        [$logger, , $stderr] = $this->createLogger();
        $authClient = $this->createMockAuthClient(true);
        $notifier = new WebhookNotifier($logger, $authClient);

        $notifier->send('ftp://localhost/webhook', ['test' => true]);

        $output = $this->readStream($stderr);
        $this->assertStringContainsString('webhook_url_invalid_scheme', $output);
    }

    public function testLogsWarningOnConnectionFailure(): void
    {
        [$logger, , $stderr] = $this->createLogger();
        $authClient = $this->createMockAuthClient(true);
        $notifier = new WebhookNotifier($logger, $authClient);

        // This will fail because the server doesn't exist — that's the point
        $notifier->send('https://localhost:19999/nonexistent-webhook', ['test' => true]);

        $output = $this->readStream($stderr);
        $this->assertStringContainsString('webhook_failed', $output);
    }
}
