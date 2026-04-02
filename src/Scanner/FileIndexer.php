<?php

namespace Legitrum\Analyzer\Scanner;

use InvalidArgumentException;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

class FileIndexer
{
    private const ALLOWED_ENVIRONMENTS = ['development', 'staging'];

    private const EXCLUDE_DIRS = [
        'node_modules', 'vendor', '.git', 'dist', '.next',
        'build', 'coverage', '.nyc_output', '__pycache__',
        '.pytest_cache', 'target', 'bin', 'obj', '.idea',
        '.vscode', '.cache', '.turbo', 'out',
        'secrets', 'config/production',
    ];

    private const EXTENSIONS = [
        'php', 'ts', 'tsx', 'js', 'jsx', 'py', 'java',
        'cs', 'go', 'rb', 'swift', 'kt', 'scala',
        'vue', 'svelte', 'html',
        'yaml', 'yml', 'json', 'toml', 'env',
    ];

    private const LOCK_FILES = [
        'package-lock.json', 'composer.lock', 'yarn.lock', 'pnpm-lock.yaml',
        'Pipfile.lock', 'Gemfile.lock', 'go.sum', 'requirements.txt',
    ];

    private const MAX_FILE_SIZE = 500 * 1024; // 500KB

    public function index(string $projectPath, string $environment = 'development'): array
    {
        if (! in_array($environment, self::ALLOWED_ENVIRONMENTS, true)) {
            throw new InvalidArgumentException("Environment '{$environment}' is not allowed. Permitted: " . implode(', ', self::ALLOWED_ENVIRONMENTS));
        }

        $files = [];
        $projectPath = rtrim($projectPath, DIRECTORY_SEPARATOR);

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($projectPath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
        );

        foreach ($iterator as $file) {
            if (! $file->isFile()) {
                continue;
            }

            $path = $file->getPathname();

            // Skip excluded directories
            foreach (self::EXCLUDE_DIRS as $dir) {
                if (str_contains($path, DIRECTORY_SEPARATOR . $dir . DIRECTORY_SEPARATOR)
                    || str_ends_with(dirname($path), DIRECTORY_SEPARATOR . $dir)) {
                    continue 2;
                }
            }

            // Skip production paths in non-production environments
            if ($this->isProductionPath($path) && $environment !== 'production') {
                continue;
            }

            // Check extension (handle blade.php)
            $ext = $file->getExtension();
            if (str_ends_with($file->getFilename(), '.blade.php')) {
                $ext = 'blade.php';
            }
            if (str_ends_with($file->getFilename(), '.env.example')) {
                $ext = 'env';
            }

            if (! in_array($ext, self::EXTENSIONS)) {
                continue;
            }

            // Skip minified/generated
            $filename = $file->getFilename();
            if (str_contains($filename, '.min.') || str_contains($filename, '.generated.')) {
                continue;
            }

            // Lock/dependency files: include but flag them
            $isLockFile = in_array($filename, self::LOCK_FILES);

            // Skip very large files (except lock files — needed for vulnerability scanning)
            if (! $isLockFile && $file->getSize() > self::MAX_FILE_SIZE) {
                continue;
            }

            $relativePath = str_replace($projectPath . DIRECTORY_SEPARATOR, '', $path);
            $relativePath = str_replace(DIRECTORY_SEPARATOR, '/', $relativePath);

            $lineCount = 0;
            $handle = fopen($path, 'r');
            if ($handle) {
                while (fgets($handle) !== false) {
                    $lineCount++;
                }
                fclose($handle);
            }

            $files[] = [
                'path' => $relativePath,
                'absolute_path' => $path,
                'extension' => $ext,
                'size' => $file->getSize(),
                'lines' => $lineCount,
                'is_lock_file' => $isLockFile,
            ];
        }

        return $files;
    }

    private function isProductionPath(string $path): bool
    {
        $normalized = str_replace(DIRECTORY_SEPARATOR, '/', strtolower($path));

        return str_contains($normalized, '/config/production/')
            || str_contains($normalized, '/config/prod/')
            || str_contains($normalized, '/deploy/production/')
            || str_contains($normalized, '/deploy/prod/')
            || str_contains($normalized, '/environments/production/')
            || str_contains($normalized, '/environments/prod/');
    }
}
