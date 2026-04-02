<?php

require __DIR__ . '/vendor/autoload.php';

use Legitrum\Analyzer\Analyzer;

// Load secrets via centralized config
$config = require __DIR__ . '/secrets/config.php';

$token = $config['LEGITRUM_TOKEN'];
$server = $config['LEGITRUM_SERVER'];
$assessmentId = $config['ASSESSMENT_ID'];
$projectPath = '/repo';
$logLevel = $config['LOG_LEVEL'];

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
