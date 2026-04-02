<?php

use Legitrum\Analyzer\ErrorHandling\ProductionExceptionHandler;
use Legitrum\Analyzer\Logging\Logger;

/**
 * Register global error and exception handlers.
 *
 * Call this before any user code executes.
 *
 * @param Logger $logger  The application logger instance
 * @param bool   $isProduction  Whether to suppress stack traces
 */
return function (Logger $logger, bool $isProduction): void {
    // Convert PHP warnings/notices to structured log entries
    set_error_handler(function (int $errno, string $errstr, string $errfile, int $errline) use ($logger, $isProduction): bool {
        // Respect error_reporting() — honour @ operator
        if (! (error_reporting() & $errno)) {
            return false;
        }

        $logger->warn($errstr, [
            'php_error_code' => $errno,
            'file' => $isProduction ? basename($errfile) : $errfile,
            'line' => $errline,
        ]);

        // Return true to prevent PHP's default error handler
        return true;
    }, E_ALL);

    // Register exception handler
    $handler = new ProductionExceptionHandler($logger, $isProduction);
    $handler->register();

    // Suppress raw error output in production
    if ($isProduction) {
        ini_set('display_errors', '0');
    }
};
