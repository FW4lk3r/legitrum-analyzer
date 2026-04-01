<?php

require __DIR__ . '/vendor/autoload.php';

use Legitrum\Analyzer\Analyzer;

$token = getenv('LEGITRUM_TOKEN') ?: die("ERROR: LEGITRUM_TOKEN not set\n");
$server = getenv('LEGITRUM_SERVER') ?: 'https://legitrum.com';
$assessmentId = getenv('ASSESSMENT_ID') ?: die("ERROR: ASSESSMENT_ID not set\n");
$projectPath = '/repo';
$logLevel = getenv('LOG_LEVEL') ?: 'info';

if (! is_dir($projectPath)) {
    die("ERROR: /repo not mounted. Use: docker run -v /path/to/project:/repo:ro\n");
}

$analyzer = new Analyzer($token, $server, $assessmentId, $projectPath, $logLevel);

try {
    $analyzer->run();
    exit(0);
} catch (\Throwable $e) {
    fwrite(STDERR, "FATAL: {$e->getMessage()}\n");
    exit(1);
}
