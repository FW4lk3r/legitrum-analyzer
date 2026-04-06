<?php

namespace Legitrum\Analyzer\Reporter;

class ReportGenerator
{
    public function generate(
        int $assessmentId,
        string $server,
        array $scanSummary,
        ?array $serverResults,
        bool $completionConfirmed = true,
    ): array {
        $report = [
            'version' => '1.0',
            'generated_at' => date('c'),
            'assessment_id' => $assessmentId,
            'server' => $server,
            'analyzer_version' => '1.0',
            'scan_summary' => $scanSummary,
        ];

        if ($serverResults === null) {
            $reason = $completionConfirmed ? 'timeout' : 'completion_not_confirmed';
            $report['results'] = [
                'available' => false,
                'reason' => $reason,
                'message' => "Results not available yet. Check {$server}/assessments/{$assessmentId}",
            ];
        } elseif (($serverResults['status'] ?? '') === 'failed') {
            $report['results'] = [
                'available' => false,
                'reason' => 'server_error',
                'message' => $serverResults['reason'] ?? 'AI pipeline failed',
            ];
        } elseif (($serverResults['status'] ?? '') === 'completed') {
            $results = $serverResults['results'] ?? [];
            $report['results'] = [
                'available' => true,
                'overall_score' => $results['overall_score'] ?? null,
                'overall_status' => $results['overall_status'] ?? null,
                'criteria' => $results['criteria'] ?? [],
            ];
        } else {
            $report['results'] = [
                'available' => false,
                'reason' => 'timeout',
                'message' => "Results not available yet. Check {$server}/assessments/{$assessmentId}",
            ];
        }

        $report['results_url'] = "{$server}/assessments/{$assessmentId}";

        return $report;
    }

    public function writeToFile(array $report, string $path): void
    {
        $realCwd = realpath(getcwd());
        $realTmp = realpath(sys_get_temp_dir());
        $dir = dirname($path);

        if (! is_dir($dir)) {
            throw new \RuntimeException("Report output directory does not exist: {$dir}");
        }

        if (! is_writable($dir)) {
            throw new \RuntimeException("Report output directory is not writable: {$dir}");
        }

        $realDir = realpath($dir);
        if ($realDir === false) {
            throw new \RuntimeException("Cannot resolve report output path: {$dir}");
        }

        $withinCwd = $realCwd !== false && strpos($realDir, $realCwd) === 0;
        $withinTmp = $realTmp !== false && strpos($realDir, $realTmp) === 0;

        if (! $withinCwd && ! $withinTmp) {
            throw new \RuntimeException(
                "Report output path must be within working directory or /tmp. Resolved to: {$realDir}"
            );
        }

        $json = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $written = file_put_contents($path, $json . "\n");

        if ($written === false) {
            throw new \RuntimeException("Failed to write report to: {$path}");
        }

        chmod($path, 0640);
    }

    public function toJson(array $report): string
    {
        return json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    public function determineExitCode(
        ?array $serverResults,
        int $complianceThreshold,
        bool $noWait,
    ): int {
        if ($noWait) {
            return 0;
        }

        if ($serverResults === null) {
            return 3;
        }

        $status = $serverResults['status'] ?? '';

        if ($status === 'failed') {
            return 3;
        }

        if ($status !== 'completed') {
            return 3;
        }

        if ($complianceThreshold === 0) {
            return 0;
        }

        $score = $serverResults['results']['overall_score'] ?? 0;

        return $score >= $complianceThreshold ? 0 : 2;
    }
}
