<?php

namespace Legitrum\Analyzer\Scanner;

use InvalidArgumentException;
use Legitrum\Analyzer\Logging\Logger;
use Legitrum\Analyzer\Security\FileValidator;

class GrepSearch
{
    private const ALLOWED_BASE_DIRS = [
        '/repo',        // Docker mount point
        '/tmp',         // Testing
    ];

    private ?FileValidator $validator = null;

    private Logger $logger;

    public function __construct(?Logger $logger = null)
    {
        $this->logger = $logger ?? new Logger();
    }

    public function setValidator(FileValidator $validator): void
    {
        $this->validator = $validator;
    }

    public function findRelevantFiles(array $allFiles, array $patterns, string $projectPath): array
    {
        $basePath = realpath($projectPath);
        if ($basePath === false || ! is_dir($basePath) || ! is_readable($basePath)) {
            throw new InvalidArgumentException("Project path is not a valid readable directory: {$projectPath}");
        }

        // Verify project path is under an allowed base directory
        $normalizedBase = str_replace('\\', '/', $basePath);
        $isAllowed = false;
        foreach (self::ALLOWED_BASE_DIRS as $allowed) {
            if (str_starts_with($normalizedBase, $allowed)) {
                $isAllowed = true;
                break;
            }
        }
        if (! $isAllowed) {
            throw new InvalidArgumentException("Project path is outside allowed base directories: {$projectPath}");
        }

        $sanitizedPatterns = $this->sanitizePatterns($patterns);

        $relevant = [];

        foreach ($allFiles as $fileInfo) {
            if (! $this->isPathSafe($fileInfo['absolute_path'], $basePath)) {
                continue;
            }

            // Skip lock files for pattern matching (used separately for SBOM/vulnerability scanning)
            if (! empty($fileInfo['is_lock_file'])) {
                continue;
            }

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

            foreach ($sanitizedPatterns as $pattern) {
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

    private function isPathSafe(string $path, string $basePath): bool
    {
        $realPath = realpath($path);
        if ($realPath === false) {
            return false;
        }

        return str_starts_with($realPath, $basePath . DIRECTORY_SEPARATOR) || $realPath === $basePath;
    }

    /**
     * @param array<mixed> $patterns
     * @return array<string>
     */
    private function sanitizePatterns(array $patterns): array
    {
        $safe = [];

        foreach ($patterns as $pattern) {
            if (! is_string($pattern) || trim($pattern) === '') {
                continue;
            }

            // stripos() uses plain strings, not regex — but validate length to prevent abuse
            if (strlen($pattern) > 1000) {
                continue;
            }

            $safe[] = $pattern;
        }

        return $safe;
    }

    /**
     * @return string|false
     */
    private bool $validatorWarningLogged = false;

    private function validateAndReadFile(string $path): string|false
    {
        if ($this->validator === null) {
            if (! $this->validatorWarningLogged) {
                $this->logger->warn('FileValidator not set — files are not being validated');
                $this->validatorWarningLogged = true;
            }
        } else {
            $result = $this->validator->validate($path);
            if ($result->rejected) {
                return false;
            }
        }

        try {
            $content = file_get_contents($path);
        } catch (\Throwable $e) {
            $this->logger->warn('Could not read file', ['path' => $path, 'error' => $e->getMessage()]);

            return false;
        }

        if ($content === false) {
            $this->logger->warn('Could not read file', ['path' => $path]);

            return false;
        }

        return $content;
    }
}
