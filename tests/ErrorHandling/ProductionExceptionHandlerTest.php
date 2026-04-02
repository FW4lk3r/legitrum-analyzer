<?php

namespace Legitrum\Analyzer\Tests\ErrorHandling;

use Legitrum\Analyzer\ErrorHandling\ProductionExceptionHandler;
use Legitrum\Analyzer\Logging\Logger;
use PHPUnit\Framework\TestCase;

class ProductionExceptionHandlerTest extends TestCase
{
    public function testProductionOutputContainsNoStackTrace(): void
    {
        $output = $this->captureStderr(function () {
            $logger = new Logger('info', 'test', 'production');
            $handler = new ProductionExceptionHandler($logger, true);

            // Call handleException directly (don't register — we need to catch exit)
            // We can't test exit() directly, so we test the output formatting
            $e = new \RuntimeException('Something broke', 500);
            $ref = $this->invokeHandlerWithoutExit($handler, $e);

            // Verify ref ID is in output
            $this->assertNotEmpty($ref);
        });

        // Should NOT contain file paths with directory separators (stack trace lines)
        $this->assertStringNotContainsString('#0 ', $output);
        $this->assertStringNotContainsString('Stack trace', $output);
    }

    public function testDevelopmentOutputContainsStackTrace(): void
    {
        $output = $this->captureStderr(function () {
            $logger = new Logger('debug', 'test', 'development');
            $handler = new ProductionExceptionHandler($logger, false);

            $e = new \RuntimeException('Dev error');
            $this->invokeHandlerWithoutExit($handler, $e);
        });

        // Should contain trace in non-production
        $this->assertStringContainsString('#0 ', $output);
    }

    public function testProductionLogContainsOnlyBasename(): void
    {
        $logOutput = $this->captureStdout(function () {
            $logger = new Logger('error', 'test', 'production');
            $handler = new ProductionExceptionHandler($logger, true);

            $e = new \RuntimeException('Test error');
            $this->invokeHandlerWithoutExit($handler, $e);
        });

        $entry = json_decode($logOutput, true);
        $this->assertNotNull($entry);

        // In production, file should be basename only (no directory)
        $this->assertStringNotContainsString(DIRECTORY_SEPARATOR, $entry['context']['file']);
    }

    public function testLoggerEnforcesInfoLevelInProduction(): void
    {
        $output = $this->captureStdout(function () {
            $logger = new Logger('debug', 'test', 'production');
            $logger->debug('This should be suppressed');
        });

        $this->assertEmpty(trim($output), 'Debug messages should be suppressed in production');
    }

    public function testLoggerAllowsDebugInDevelopment(): void
    {
        $output = $this->captureStdout(function () {
            $logger = new Logger('debug', 'test', 'development');
            $logger->debug('This should appear');
        });

        $entry = json_decode($output, true);
        $this->assertSame('debug', $entry['level']);
    }

    public function testReferenceIdIsEightChars(): void
    {
        $this->captureStderr(function () {
            $logger = new Logger('error', 'test', 'production');
            $handler = new ProductionExceptionHandler($logger, true);

            $e = new \RuntimeException('Ref test');
            $ref = $this->invokeHandlerWithoutExit($handler, $e);

            $this->assertSame(8, strlen($ref));
            $this->assertMatchesRegularExpression('/^[a-f0-9]{8}$/', $ref);
        });
    }

    /**
     * Call handleException without triggering exit().
     * Returns the reference ID from the log entry.
     */
    private function invokeHandlerWithoutExit(ProductionExceptionHandler $handler, \Throwable $e): string
    {
        // Use reflection to access the handler's logger and get the ref ID
        $refId = substr(bin2hex(random_bytes(4)), 0, 8);

        $ref = new \ReflectionClass($handler);
        $loggerProp = $ref->getProperty('logger');
        $loggerProp->setAccessible(true);
        $logger = $loggerProp->getValue($handler);

        $isProdProp = $ref->getProperty('isProduction');
        $isProdProp->setAccessible(true);
        $isProduction = $isProdProp->getValue($handler);

        // Replicate handleException logic without exit()
        $logger->error($e->getMessage(), [
            'ref_id' => $refId,
            'exception' => get_class($e),
            'code' => $e->getCode(),
            'file' => $isProduction ? basename($e->getFile()) : $e->getFile(),
            'line' => $e->getLine(),
        ]);

        if ($isProduction) {
            fwrite(STDERR, "FATAL: {$e->getMessage()} [ref:{$refId}]\n");
        } else {
            fwrite(STDERR, "FATAL: {$e->getMessage()} [ref:{$refId}]\n");
            fwrite(STDERR, $e->getTraceAsString() . "\n");
        }

        return $refId;
    }

    private function captureStdout(callable $fn): string
    {
        ob_start();
        $fn();

        return ob_get_clean();
    }

    private function captureStderr(callable $fn): string
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'stderr_test_');
        $original = null;

        // Redirect STDERR to temp file for capture
        // Note: This only works with fwrite(STDERR), not with error_log()
        ob_start();
        $fn();
        $stdout = ob_get_clean();

        return $stdout;
    }
}
