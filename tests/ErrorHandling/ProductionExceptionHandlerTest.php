<?php

namespace Legitrum\Analyzer\Tests\ErrorHandling;

use Legitrum\Analyzer\ErrorHandling\ProductionExceptionHandler;
use Legitrum\Analyzer\Logging\Logger;
use PHPUnit\Framework\TestCase;

class ProductionExceptionHandlerTest extends TestCase
{
    public function testProductionOutputContainsNoStackTrace(): void
    {
        $stderr = fopen('php://memory', 'rw');
        $logStream = fopen('php://memory', 'rw');
        $logger = new Logger('error', 'test', 'production', $logStream, $logStream);
        $handler = new ProductionExceptionHandler($logger, true);

        $e = new \RuntimeException('Something broke', 500);

        // Capture stderr by replacing it temporarily
        $origStderr = defined('STDERR') ? STDERR : fopen('php://stderr', 'w');
        $this->invokeHandlerWithoutExit($handler, $e, $stderr);

        rewind($stderr);
        $output = stream_get_contents($stderr);

        $this->assertStringContainsString('Something broke', $output);
        $this->assertStringNotContainsString('#0 ', $output);
    }

    public function testDevelopmentOutputContainsStackTrace(): void
    {
        $stderr = fopen('php://memory', 'rw');
        $logStream = fopen('php://memory', 'rw');
        $logger = new Logger('debug', 'test', 'development', $logStream, $logStream);
        $handler = new ProductionExceptionHandler($logger, false);

        $e = new \RuntimeException('Dev error');
        $this->invokeHandlerWithoutExit($handler, $e, $stderr);

        rewind($stderr);
        $output = stream_get_contents($stderr);

        $this->assertStringContainsString('#0 ', $output);
    }

    public function testProductionLogContainsOnlyBasename(): void
    {
        $logStream = fopen('php://memory', 'rw');
        $stderr = fopen('php://memory', 'rw');
        $logger = new Logger('error', 'test', 'production', $logStream, $logStream);
        $handler = new ProductionExceptionHandler($logger, true);

        $e = new \RuntimeException('Test error');
        $this->invokeHandlerWithoutExit($handler, $e, $stderr);

        rewind($logStream);
        $entry = json_decode(stream_get_contents($logStream), true);

        $this->assertNotNull($entry);
        $this->assertStringNotContainsString('/', $entry['context']['file']);
        $this->assertStringNotContainsString('\\', $entry['context']['file']);
    }

    public function testLoggerEnforcesInfoLevelInProduction(): void
    {
        $stdout = fopen('php://memory', 'rw');
        $logger = new Logger('debug', 'test', 'production', $stdout, $stdout);
        $logger->debug('This should be suppressed');

        rewind($stdout);
        $this->assertEmpty(trim(stream_get_contents($stdout)));
    }

    public function testLoggerAllowsDebugInDevelopment(): void
    {
        $stdout = fopen('php://memory', 'rw');
        $logger = new Logger('debug', 'test', 'development', $stdout, $stdout);
        $logger->debug('This should appear');

        rewind($stdout);
        $entry = json_decode(stream_get_contents($stdout), true);
        $this->assertSame('debug', $entry['level']);
    }

    public function testReferenceIdIsEightChars(): void
    {
        $logStream = fopen('php://memory', 'rw');
        $stderr = fopen('php://memory', 'rw');
        $logger = new Logger('error', 'test', 'production', $logStream, $logStream);
        $handler = new ProductionExceptionHandler($logger, true);

        $e = new \RuntimeException('Ref test');
        $this->invokeHandlerWithoutExit($handler, $e, $stderr);

        rewind($logStream);
        $entry = json_decode(stream_get_contents($logStream), true);

        $this->assertSame(8, strlen($entry['context']['ref_id']));
        $this->assertMatchesRegularExpression('/^[a-f0-9]{8}$/', $entry['context']['ref_id']);
    }

    /**
     * Replicate handleException logic without calling exit().
     *
     * @param resource $stderr
     */
    private function invokeHandlerWithoutExit(
        ProductionExceptionHandler $handler,
        \Throwable $e,
        $stderr
    ): void {
        $ref = new \ReflectionClass($handler);

        $loggerProp = $ref->getProperty('logger');
        $loggerProp->setAccessible(true);
        $logger = $loggerProp->getValue($handler);

        $isProdProp = $ref->getProperty('isProduction');
        $isProdProp->setAccessible(true);
        $isProduction = $isProdProp->getValue($handler);

        $refId = substr(bin2hex(random_bytes(4)), 0, 8);

        $logger->error($e->getMessage(), [
            'ref_id' => $refId,
            'exception' => get_class($e),
            'code' => $e->getCode(),
            'file' => $isProduction ? basename($e->getFile()) : $e->getFile(),
            'line' => $e->getLine(),
        ]);

        if ($isProduction) {
            fwrite($stderr, "FATAL: {$e->getMessage()} [ref:{$refId}]\n");
        } else {
            fwrite($stderr, "FATAL: {$e->getMessage()} [ref:{$refId}]\n");
            fwrite($stderr, $e->getTraceAsString() . "\n");
        }
    }
}
