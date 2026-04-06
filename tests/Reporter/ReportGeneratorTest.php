<?php

namespace Legitrum\Analyzer\Tests\Reporter;

use Legitrum\Analyzer\Reporter\ReportGenerator;
use PHPUnit\Framework\TestCase;

class ReportGeneratorTest extends TestCase
{
    private ReportGenerator $generator;

    protected function setUp(): void
    {
        $this->generator = new ReportGenerator();
    }

    private function baseScanSummary(): array
    {
        return [
            'total_files_analyzed' => 150,
            'total_lines_analyzed' => 25000,
            'criteria_evaluated' => 12,
            'duration_seconds' => 45,
            'sbom_submitted' => true,
            'files_rejected' => 2,
            'files_warned' => 1,
        ];
    }

    private function completedResults(int $score = 78): array
    {
        return [
            'status' => 'completed',
            'assessment_id' => 123,
            'completed_at' => '2026-04-07T14:30:00Z',
            'results' => [
                'overall_score' => $score,
                'overall_status' => 'partially_compliant',
                'criteria' => [
                    [
                        'id' => 45,
                        'title' => 'A06:2021 - Vulnerable Components',
                        'status' => 'compliant',
                        'score' => 85,
                        'findings' => ['Evidence found'],
                        'recommendations' => ['Add SBOM'],
                    ],
                ],
            ],
        ];
    }

    public function testGenerateWithCompletedResults(): void
    {
        $report = $this->generator->generate(
            123,
            'https://app.legitrum.pt',
            $this->baseScanSummary(),
            $this->completedResults(),
        );

        $this->assertSame('1.0', $report['version']);
        $this->assertSame(123, $report['assessment_id']);
        $this->assertSame('https://app.legitrum.pt', $report['server']);
        $this->assertTrue($report['results']['available']);
        $this->assertSame(78, $report['results']['overall_score']);
        $this->assertSame('partially_compliant', $report['results']['overall_status']);
        $this->assertCount(1, $report['results']['criteria']);
        $this->assertSame('https://app.legitrum.pt/assessments/123', $report['results_url']);
    }

    public function testGenerateWithNullResultsShowsTimeout(): void
    {
        $report = $this->generator->generate(
            123,
            'https://app.legitrum.pt',
            $this->baseScanSummary(),
            null,
        );

        $this->assertFalse($report['results']['available']);
        $this->assertSame('timeout', $report['results']['reason']);
        $this->assertStringContainsString('assessments/123', $report['results']['message']);
    }

    public function testGenerateWithFailedResults(): void
    {
        $report = $this->generator->generate(
            123,
            'https://app.legitrum.pt',
            $this->baseScanSummary(),
            ['status' => 'failed', 'reason' => 'model_timeout'],
        );

        $this->assertFalse($report['results']['available']);
        $this->assertSame('server_error', $report['results']['reason']);
    }

    public function testGenerateWithCompletionNotConfirmed(): void
    {
        $report = $this->generator->generate(
            123,
            'https://app.legitrum.pt',
            $this->baseScanSummary(),
            null,
            false,
        );

        $this->assertFalse($report['results']['available']);
        $this->assertSame('completion_not_confirmed', $report['results']['reason']);
    }

    public function testGenerateIncludesScanSummary(): void
    {
        $report = $this->generator->generate(
            123,
            'https://app.legitrum.pt',
            $this->baseScanSummary(),
            $this->completedResults(),
        );

        $this->assertSame(150, $report['scan_summary']['total_files_analyzed']);
        $this->assertSame(25000, $report['scan_summary']['total_lines_analyzed']);
        $this->assertSame(12, $report['scan_summary']['criteria_evaluated']);
        $this->assertTrue($report['scan_summary']['sbom_submitted']);
    }

    public function testToJsonReturnsValidJson(): void
    {
        $report = $this->generator->generate(
            123,
            'https://app.legitrum.pt',
            $this->baseScanSummary(),
            $this->completedResults(),
        );

        $json = $this->generator->toJson($report);
        $decoded = json_decode($json, true);

        $this->assertNotNull($decoded);
        $this->assertSame(123, $decoded['assessment_id']);
    }

    public function testWriteToFileCreatesFileWithCorrectPermissions(): void
    {
        $tmpFile = tempnam(sys_get_temp_dir(), 'legitrum_test_');

        $report = $this->generator->generate(
            123,
            'https://app.legitrum.pt',
            $this->baseScanSummary(),
            $this->completedResults(),
        );

        $this->generator->writeToFile($report, $tmpFile);

        $this->assertFileExists($tmpFile);
        $content = json_decode(file_get_contents($tmpFile), true);
        $this->assertSame(123, $content['assessment_id']);

        // Check permissions (Unix only)
        if (PHP_OS_FAMILY !== 'Windows') {
            $perms = fileperms($tmpFile) & 0777;
            $this->assertSame(0640, $perms);
        }

        unlink($tmpFile);
    }

    public function testWriteToFileRejectsPathOutsideCwdAndTmp(): void
    {
        // Only test on Unix where /etc exists and is outside cwd/tmp
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('Path traversal test requires Unix filesystem');
        }

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('working directory or /tmp');

        $this->generator->writeToFile(['test' => true], '/etc/legitrum-report.json');
    }

    // --- Exit code tests ---

    public function testExitCodeZeroWhenCompliantAboveThreshold(): void
    {
        $this->assertSame(0, $this->generator->determineExitCode(
            $this->completedResults(80),
            70,
            false,
        ));
    }

    public function testExitCodeTwoWhenBelowThreshold(): void
    {
        $this->assertSame(2, $this->generator->determineExitCode(
            $this->completedResults(50),
            70,
            false,
        ));
    }

    public function testExitCodeThreeWhenResultsNull(): void
    {
        $this->assertSame(3, $this->generator->determineExitCode(
            null,
            100,
            false,
        ));
    }

    public function testExitCodeThreeWhenResultsFailed(): void
    {
        $this->assertSame(3, $this->generator->determineExitCode(
            ['status' => 'failed', 'reason' => 'pipeline_error'],
            100,
            false,
        ));
    }

    public function testExitCodeZeroInNoWaitMode(): void
    {
        $this->assertSame(0, $this->generator->determineExitCode(
            null,
            100,
            true,
        ));
    }

    public function testExitCodeZeroWhenThresholdIsZero(): void
    {
        $this->assertSame(0, $this->generator->determineExitCode(
            $this->completedResults(10),
            0,
            false,
        ));
    }

    public function testExitCodeZeroWhenScoreEqualsThreshold(): void
    {
        $this->assertSame(0, $this->generator->determineExitCode(
            $this->completedResults(70),
            70,
            false,
        ));
    }

    public function testExitCodeThreeWhenStatusIsProcessing(): void
    {
        $this->assertSame(3, $this->generator->determineExitCode(
            ['status' => 'processing'],
            100,
            false,
        ));
    }
}
