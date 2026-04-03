<?php

namespace Legitrum\Analyzer\Tests\Logging;

use Legitrum\Analyzer\Logging\Logger;
use PHPUnit\Framework\TestCase;

class LoggerTest extends TestCase
{
    private function createLogger(string $level = 'info', ?string $appEnv = null): array
    {
        $stdout = fopen('php://memory', 'rw');
        $stderr = fopen('php://memory', 'rw');
        $logger = new Logger($level, 'legitrum-analyzer', $appEnv, $stdout, $stderr);

        return [$logger, $stdout, $stderr];
    }

    private function readStream($stream): string
    {
        rewind($stream);

        return stream_get_contents($stream);
    }

    public function testOutputsStructuredJson(): void
    {
        [$logger, $stdout] = $this->createLogger();
        $logger->info('Test message', ['key' => 'value']);

        $entry = json_decode($this->readStream($stdout), true);

        $this->assertNotNull($entry, 'Output must be valid JSON');
        $this->assertSame('info', $entry['level']);
        $this->assertSame('Test message', $entry['message']);
        $this->assertSame('legitrum-analyzer', $entry['service']);
        $this->assertArrayHasKey('timestamp', $entry);
        $this->assertSame(['key' => 'value'], $entry['context']);
    }

    public function testRedactsSensitiveKeys(): void
    {
        [$logger, $stdout] = $this->createLogger();
        $logger->info('Auth attempt', [
            'username' => 'admin',
            'password' => 'secret123',
            'api_key' => 'sk-abc',
            'token' => 'Bearer xyz',
        ]);

        $entry = json_decode($this->readStream($stdout), true);
        $ctx = $entry['context'];

        $this->assertSame('admin', $ctx['username']);
        $this->assertSame('[REDACTED]', $ctx['password']);
        $this->assertSame('[REDACTED]', $ctx['api_key']);
        $this->assertSame('[REDACTED]', $ctx['token']);
    }

    public function testRedactsNestedSensitiveKeys(): void
    {
        [$logger, $stdout] = $this->createLogger();
        $logger->info('Nested', [
            'config' => [
                'host' => 'localhost',
                'secret_key' => 'abc123',
            ],
        ]);

        $entry = json_decode($this->readStream($stdout), true);

        $this->assertSame('localhost', $entry['context']['config']['host']);
        $this->assertSame('[REDACTED]', $entry['context']['config']['secret_key']);
    }

    public function testRedactsPiiFields(): void
    {
        [$logger, $stdout] = $this->createLogger();
        $logger->info('User data', [
            'username' => 'john',
            'ssn' => '123-45-6789',
            'credit_card' => '4111111111111111',
            'cvv' => '123',
            'national_id' => 'PT123456',
            'passport' => 'AB123456',
            'bank_account' => 'PT50000201231234567890154',
            'health_data' => 'diagnosis xyz',
            'medical_record' => 'record-123',
        ]);

        $entry = json_decode($this->readStream($stdout), true);
        $ctx = $entry['context'];

        $this->assertSame('john', $ctx['username']);
        $this->assertSame('[REDACTED]', $ctx['ssn']);
        $this->assertSame('[REDACTED]', $ctx['credit_card']);
        $this->assertSame('[REDACTED]', $ctx['cvv']);
        $this->assertSame('[REDACTED]', $ctx['national_id']);
        $this->assertSame('[REDACTED]', $ctx['passport']);
        $this->assertSame('[REDACTED]', $ctx['bank_account']);
        $this->assertSame('[REDACTED]', $ctx['health_data']);
        $this->assertSame('[REDACTED]', $ctx['medical_record']);
    }

    public function testRespectsLogLevel(): void
    {
        [$logger, $stdout, $stderr] = $this->createLogger('warn');
        $logger->debug('Should not appear');
        $logger->info('Should not appear');

        $this->assertEmpty(trim($this->readStream($stdout)));
        $this->assertEmpty(trim($this->readStream($stderr)));
    }

    public function testDebugLevelShowsEverything(): void
    {
        [$logger, $stdout] = $this->createLogger('debug');
        $logger->debug('Debug msg');

        $entry = json_decode($this->readStream($stdout), true);
        $this->assertSame('debug', $entry['level']);
    }

    public function testContainsTimestampInIso8601(): void
    {
        [$logger, $stdout] = $this->createLogger();
        $logger->info('Timestamp test');

        $entry = json_decode($this->readStream($stdout), true);

        $this->assertNotFalse(
            \DateTimeImmutable::createFromFormat(\DateTimeInterface::ATOM, $entry['timestamp']),
            'Timestamp must be ISO 8601'
        );
    }

    public function testOmitsContextWhenEmpty(): void
    {
        [$logger, $stdout] = $this->createLogger();
        $logger->info('No context');

        $entry = json_decode($this->readStream($stdout), true);
        $this->assertArrayNotHasKey('context', $entry);
    }

    public function testWarnWritesToStderr(): void
    {
        [$logger, $stdout, $stderr] = $this->createLogger();
        $logger->warn('Warning msg');

        $this->assertEmpty(trim($this->readStream($stdout)));
        $entry = json_decode($this->readStream($stderr), true);
        $this->assertSame('warn', $entry['level']);
    }

    public function testErrorWritesToStderr(): void
    {
        [$logger, $stdout, $stderr] = $this->createLogger();
        $logger->error('Error msg');

        $this->assertEmpty(trim($this->readStream($stdout)));
        $entry = json_decode($this->readStream($stderr), true);
        $this->assertSame('error', $entry['level']);
    }

    public function testProductionEnforcesInfoLevel(): void
    {
        [$logger, $stdout] = $this->createLogger('debug', 'production');
        $logger->debug('Should be suppressed');

        $this->assertEmpty(trim($this->readStream($stdout)));
    }
}
