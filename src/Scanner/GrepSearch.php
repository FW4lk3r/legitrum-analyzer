<?php

namespace Legitrum\Analyzer\Scanner;

use Legitrum\Analyzer\Security\FileValidator;

class GrepSearch
{
    private ?FileValidator $validator = null;

    public function setValidator(FileValidator $validator): void
    {
        $this->validator = $validator;
    }

    public function findRelevantFiles(array $allFiles, array $patterns, string $projectPath): array
    {
        $relevant = [];

        foreach ($allFiles as $fileInfo) {
            $content = $this->validateAndReadFile($fileInfo['absolute_path']);
            if ($content === false) {
                continue;
            }

            // Sanitize UTF-8
            $content = mb_convert_encoding($content, 'UTF-8', 'auto');
            if (! mb_check_encoding($content, 'UTF-8')) {
                $content = iconv('UTF-8', 'UTF-8//IGNORE', $content);
            }

            $score = 0;
            $matchedPatterns = [];

            foreach ($patterns as $pattern) {
                if (stripos($content, $pattern) !== false) {
                    $score++;
                    $matchedPatterns[] = $pattern;
                }
            }

            if ($score > 0) {
                $relevant[] = array_merge($fileInfo, [
                    'relevance_score' => $score,
                    'matched_patterns' => $matchedPatterns,
                    'content' => $content,
                ]);
            }
        }

        usort($relevant, fn ($a, $b) => $b['relevance_score'] - $a['relevance_score']);

        return $relevant;
    }

    /**
     * @return string|false
     */
    private function validateAndReadFile(string $path): string|false
    {
        if ($this->validator !== null) {
            $result = $this->validator->validate($path);
            if ($result->rejected) {
                return false;
            }
        }

        return @file_get_contents($path);
    }
}
