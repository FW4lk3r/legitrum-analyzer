<?php

namespace Legitrum\Analyzer\Security;

class FileValidator
{
    private const MAGIC_BYTES = [
        'php'  => ["\x3C\x3Fphp", "\x3C\x3F\x3D"],  // <?php, <?=
        'js'   => [],
        'ts'   => [],
        'json' => ['{', '['],
        'xml'  => ["\x3C\x3Fxml", '<'],
        'yaml' => [],
        'yml'  => [],
        'py'   => [],
        'rb'   => [],
        'java' => [],
        'go'   => [],
        'rs'   => [],
        'sh'   => ['#!/'],
        'bash' => ['#!/'],
        'sql'  => [],
        'md'   => [],
        'txt'  => [],
        'env'  => [],
        'css'  => [],
        'html' => ["\x3C!", '<h', '<d', '<html', '<HTML'],
        'htm'  => ["\x3C!", '<h', '<d', '<html', '<HTML'],
    ];

    private const SUSPICIOUS_HEADERS = [
        "\x50\x4B\x03\x04",  // ZIP
        "\x1F\x8B",          // GZIP
        "\x7F\x45\x4C\x46",  // ELF binary
        "\x4D\x5A",          // PE/MZ executable
        "\xCA\xFE\xBA\xBE",  // Mach-O / Java class
        "\x89\x50\x4E\x47",  // PNG
        "\xFF\xD8\xFF",      // JPEG
        "\x25\x50\x44\x46",  // PDF
    ];

    private const ENTROPY_THRESHOLD = 6.5;

    private const ENTROPY_SAMPLE_SIZE = 4096;

    private array $cache = [];

    private bool $enabled;

    public function __construct(?bool $enabled = null)
    {
        $this->enabled = $enabled ?? $this->resolveDefault();
    }

    public function validate(string $path): ValidationResult
    {
        if (! $this->enabled) {
            return ValidationResult::pass();
        }

        $hash = md5($path . filemtime($path));
        if (isset($this->cache[$hash])) {
            return $this->cache[$hash];
        }

        $result = $this->performValidation($path);
        $this->cache[$hash] = $result;

        return $result;
    }

    public function getSummary(): array
    {
        $rejected = 0;
        $warnings = 0;
        $reasons = [];

        foreach ($this->cache as $result) {
            if ($result->rejected) {
                $rejected++;
                $reasons[] = $result->reason;
            } elseif ($result->warning) {
                $warnings++;
            }
        }

        return [
            'files_validated' => count($this->cache),
            'rejected' => $rejected,
            'warnings' => $warnings,
            'rejection_reasons' => array_count_values($reasons),
        ];
    }

    private function performValidation(string $path): ValidationResult
    {
        $header = @file_get_contents($path, false, null, 0, 64);
        if ($header === false) {
            return ValidationResult::reject('unreadable');
        }

        // Check for suspicious binary headers (polyglot detection)
        foreach (self::SUSPICIOUS_HEADERS as $sig) {
            if (str_starts_with($header, $sig)) {
                return ValidationResult::reject('suspicious_binary_header');
            }
        }

        // Validate magic bytes against extension
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if (isset(self::MAGIC_BYTES[$ext]) && ! empty(self::MAGIC_BYTES[$ext])) {
            $trimmed = ltrim($header, "\xEF\xBB\xBF\r\n\t ");  // strip BOM and whitespace
            $matched = false;
            foreach (self::MAGIC_BYTES[$ext] as $expected) {
                if (str_starts_with($trimmed, $expected)) {
                    $matched = true;
                    break;
                }
            }
            if (! $matched) {
                return ValidationResult::reject("magic_mismatch:$ext");
            }
        }

        // High-entropy binary content check
        $sample = @file_get_contents($path, false, null, 0, self::ENTROPY_SAMPLE_SIZE);
        if ($sample !== false && strlen($sample) > 256) {
            $entropy = $this->shannonEntropy($sample);
            if ($entropy > self::ENTROPY_THRESHOLD) {
                return ValidationResult::warn('high_entropy');
            }
        }

        return ValidationResult::pass();
    }

    private function shannonEntropy(string $data): float
    {
        $len = strlen($data);
        $freq = array_count_values(str_split($data));
        $entropy = 0.0;

        foreach ($freq as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }

    private function resolveDefault(): bool
    {
        $env = getenv('ENABLE_STRICT_VALIDATION');
        if ($env !== false) {
            return filter_var($env, FILTER_VALIDATE_BOOLEAN);
        }

        // Default: true in staging, true otherwise (opt-out via env)
        return true;
    }
}
