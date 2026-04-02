<?php

/**
 * Centralized secret loading with validation.
 *
 * All secrets are loaded via environment variables.
 * In production, these should be injected by a vault solution
 * (e.g., HashiCorp Vault, AWS Secrets Manager, Docker Swarm secrets).
 *
 * TODO: Integrate vault client for encryption-at-rest.
 *       Replace getenv() calls with vault lookups when available.
 *       Example: $vault->get('legitrum/analyzer/token')
 */

return (function (): array {
    $token = getenv('LEGITRUM_TOKEN');
    if (! $token || trim($token) === '') {
        fwrite(STDERR, "[" . date('c') . "] FATAL: LEGITRUM_TOKEN is not set or empty\n");
        exit(1);
    }
    fwrite(STDERR, "[" . date('c') . "] Secret loaded: LEGITRUM_TOKEN (length=" . strlen($token) . ")\n");

    $assessmentId = getenv('ASSESSMENT_ID');
    if (! $assessmentId || trim($assessmentId) === '') {
        fwrite(STDERR, "[" . date('c') . "] FATAL: ASSESSMENT_ID is not set or empty\n");
        exit(1);
    }
    fwrite(STDERR, "[" . date('c') . "] Config loaded: ASSESSMENT_ID={$assessmentId}\n");

    $server = getenv('LEGITRUM_SERVER') ?: 'https://legitrum.com';
    fwrite(STDERR, "[" . date('c') . "] Config loaded: LEGITRUM_SERVER={$server}\n");

    $logLevel = getenv('LOG_LEVEL') ?: 'info';

    return [
        'LEGITRUM_TOKEN' => $token,
        'LEGITRUM_SERVER' => $server,
        'ASSESSMENT_ID' => $assessmentId,
        'LOG_LEVEL' => $logLevel,
    ];
})();
