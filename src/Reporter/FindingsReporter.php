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
}
