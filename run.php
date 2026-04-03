<?php

require __DIR__ . '/vendor/autoload.php';

use Legitrum\Analyzer\Analyzer;
use Legitrum\Analyzer\Logging\Logger;

// Load secrets via centralized config
$config = require __DIR__ . '/secrets/config.php';

$token = $config['LEGITRUM_TOKEN'];
$server = $config['LEGITRUM_SERVER'];
$assessmentId = $config['ASSESSMENT_ID'];
$projectPath = '/repo';
$logLevel = $config['LOG_LEVEL'];
$appEnv = getenv('APP_ENV') ?: 'development';
$isProduction = $appEnv === 'production';
$logDestination = getenv('LOG_DESTINATION') ?: 'stderr';

// Validate log destination is accessible before initializing
if ($logDestination !== 'stderr') {
    $logDir = dirname($logDestination);
    if (! is_dir($logDir) && ! mkdir($logDir, 0750, true)) {
        die("ERROR: Log directory is not writable: {$logDir}\n");
    }
    if (is_file($logDestination) && ! is_writable($logDestination)) {
        die("ERROR: Log file is not writable: {$logDestination}\n");
    }
}

// Register error/exception handlers before any user code
$logger = new Logger($logLevel, 'legitrum-analyzer', $appEnv, logDestination: $logDestination);
$registerHandlers = require __DIR__ . '/bootstrap/handlers.php';
$registerHandlers($logger, $isProduction);

// Block production usage — this tool is for development/staging only
if ($isProduction) {
    fwrite(STDERR, "ERROR: Analyzer is blocked in production. Set APP_ENV=development or APP_ENV=staging.\n");
    exit(1);
}

// Validate assessment ID is numeric
if (! ctype_digit((string) $assessmentId)) {
    die("ERROR: ASSESSMENT_ID must be a numeric value, got: {$assessmentId}\n");
}

// Validate log level
if (! in_array($logLevel, ['info', 'debug'], true)) {
    die("ERROR: LOG_LEVEL must be 'info' or 'debug', got: {$logLevel}\n");
}

// Validate project path exists, is readable, and is within /repo
$realProjectPath = realpath($projectPath);
if ($realProjectPath === false || ! is_dir($realProjectPath) || ! is_readable($realProjectPath)) {
    die("ERROR: /repo not mounted or unreadable. Use: docker run -v /path/to/project:/repo:ro\n");
}
if (strpos($realProjectPath, '/repo') !== 0) {
    die("ERROR: Project path must be within /repo, resolved to: {$realProjectPath}\n");
}

$analyzer = new Analyzer($token, $server, $assessmentId, $projectPath, $logLevel);
$analyzer->run();
exit(0);
