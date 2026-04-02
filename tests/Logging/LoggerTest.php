<?php

namespace Legitrum\Analyzer\Tests\Logging;

use Legitrum\Analyzer\Logging\Logger;
use PHPUnit\Framework\TestCase;

class LoggerTest extends TestCase
{
    public function testOutputsStructuredJson(): void
    {
        $output = $this->captureOutput(function () {
            $logger = new Logger('info');
            $logger->info('Test message', ['key' => 'value']);
        });

        $entry = json_decode($output, true);

        $this->assertNotNull($entry, 'Output must be valid JSON');
        $this->assertSame('info', $entry['level']);
        $this->assertSame('Test message', $entry['message']);
        $this->assertSame('legitrum-analyzer', $entry['service']);
        $this->assertArrayHasKey('timestamp', $entry);
        $this->assertSame(['key' => 'value'], $entry['context']);
    }

    public function testRedactsSensitiveKeys(): void
    {
        $output = $this->captureOutput(function () {
            $logger = new Logger('info');
            $logger->info('Auth attempt', [
                'username' => 'admin',
                'password' => 'secret123',
                'api_key' => 'sk-abc',
                'token' => 'Bearer xyz',
            ]);
        });

        $entry = json_decode($output, true);
        $ctx = $entry['context'];

        $this->assertSame('admin', $ctx['username']);
        $this->assertSame('[REDACTED]', $ctx['password']);
        $this->assertSame('[REDACTED]', $ctx['api_key']);
        $this->assertSame('[REDACTED]', $ctx['token']);
    }

    public function testRedactsNestedSensitiveKeys(): void
    {
        $output = $this->captureOutput(function () {
            $logger = new Logger('info');
            $logger->info('Nested', [
                'config' => [
                    'host' => 'localhost',
                    'secret_key' => 'abc123',
                ],
            ]);
        });

        $entry = json_decode($output, true);

        $this->assertSame('localhost', $entry['context']['config']['host']);
        $this->assertSame('[REDACTED]', $entry['context']['config']['secret_key']);
    }

    public function testRespectsLogLevel(): void
    {
        $output = $this->captureOutput(function () {
            $logger = new Logger('warn');
            $logger->debug('Should not appear');
            $logger->info('Should not appear');
        });

        $this->assertEmpty(trim($output), 'Debug and info messages should be suppressed at warn level');
    }

    public function testDebugLevelShowsEverything(): void
    {
        $output = $this->captureOutput(function () {
            $logger = new Logger('debug');
            $logger->debug('Debug msg');
        });

        $entry = json_decode($output, true);
        $this->assertSame('debug', $entry['level']);
    }

    public function testContainsTimestampInIso8601(): void
    {
        $output = $this->captureOutput(function () {
            $logger = new Logger('info');
            $logger->info('Timestamp test');
        });

        $entry = json_decode($output, true);

        // ISO 8601 format check
        $this->assertNotFalse(
            \DateTimeImmutable::createFromFormat(\DateTimeInterface::ATOM, $entry['timestamp']),
            'Timestamp must be ISO 8601'
        );
    }

    public function testOmitsContextWhenEmpty(): void
    {
        $output = $this->captureOutput(function () {
            $logger = new Logger('info');
            $logger->info('No context');
        });

        $entry = json_decode($output, true);
        $this->assertArrayNotHasKey('context', $entry);
    }

    private function captureOutput(callable $fn): string
    {
        ob_start();
        $fn();

        return ob_get_clean();
    }
}
