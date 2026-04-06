<?php

namespace Legitrum\Analyzer\Reporter;

class FindingsReporter
{
    public function formatProgress(int $current, int $total, string $criterionTitle): string
    {
        $percent = $total > 0 ? (int) round(($current / $total) * 100) : 0;
        $bar = str_repeat('█', (int) ($percent / 5)) . str_repeat('░', 20 - (int) ($percent / 5));

        return "[{$bar}] {$percent}% ({$current}/{$total}) {$criterionTitle}";
    }

    public function formatSummary(int $totalFiles, int $totalLines, int $criteriaCount, float $duration): string
    {
        return sprintf(
            "\n=== Analise concluida ===\n" .
            "Ficheiros analisados: %s\n" .
            "Linhas de codigo: %s\n" .
            "Criterios avaliados: %d\n" .
            "Duracao: %.1f min\n",
            number_format($totalFiles),
            number_format($totalLines),
            $criteriaCount,
            $duration / 60,
        );
    }

    public function formatResults(?array $serverResults, string $resultsUrl, int $complianceThreshold): string
    {
        if ($serverResults === null || ($serverResults['status'] ?? '') !== 'completed') {
            $reason = 'a processar no servidor';
            if ($serverResults !== null && ($serverResults['status'] ?? '') === 'failed') {
                $reason = 'falhou no servidor — ' . ($serverResults['reason'] ?? 'razao desconhecida');
            }

            return sprintf(
                "\n=== Resultados ===\n" .
                "Resultados: %s\n" .
                "Ver resultados em: %s\n",
                $reason,
                $resultsUrl,
            );
        }

        $results = $serverResults['results'] ?? [];
        $score = $results['overall_score'] ?? 0;
        $status = $results['overall_status'] ?? 'unknown';
        $criteria = $results['criteria'] ?? [];

        $lines = [
            '',
            '=== Resultados ===',
            sprintf('Score global: %d/100 (%s)', $score, $status),
        ];

        foreach ($criteria as $criterion) {
            $cScore = $criterion['score'] ?? 0;
            $cTitle = $criterion['title'] ?? 'Unknown';
            $tag = $this->scoreTag($cScore, $complianceThreshold);
            $lines[] = sprintf('  [%s] %s (%d/100)', $tag, $cTitle, $cScore);
        }

        $lines[] = '';
        $lines[] = "Ver detalhes em: {$resultsUrl}";

        return implode("\n", $lines) . "\n";
    }

    private function scoreTag(int $score, int $threshold): string
    {
        if ($score >= $threshold) {
            return 'PASS';
        }
        if ($score >= $threshold * 0.7) {
            return 'WARN';
        }

        return 'FAIL';
    }
}
