<?php

namespace Legitrum\Analyzer\Logging;

class Logger
{
    private const LEVELS = ['debug' => 0, 'info' => 1, 'warn' => 2, 'error' => 3];

    private const SENSITIVE_KEYS = [
        'password', 'token', 'secret', 'authorization', 'cookie',
        'api_key', 'apikey', 'credential', 'private_key',
        'ssn', 'credit_card', 'cvv', 'national_id', 'passport',
        'bank_account', 'health_data', 'medical',
    ];

    private int $minLevel;

    private string $service;

    /** @var resource */
    private $output;

    /** @var resource */
    private $errorOutput;

    /**
     * @param resource|null $output       Override stdout stream (for testing)
     * @param resource|null $errorOutput  Override stderr stream (for testing)
     */
    public function __construct(
        string $level = 'info',
        string $service = 'legitrum-analyzer',
        ?string $appEnv = null,
        $output = null,
        $errorOutput = null,
        ?string $logDestination = null,
    ) {
        $appEnv = $appEnv ?? (getenv('APP_ENV') ?: 'development');

        // Enforce minimum 'info' level in production
        if ($appEnv === 'production' && $level === 'debug') {
            $level = 'info';
        }

        $this->minLevel = self::LEVELS[$level] ?? self::LEVELS['info'];
        $this->service = $service;

        // If explicit streams provided (testing), use those
        if ($output !== null || $errorOutput !== null) {
            $this->output = $output ?? fopen('php://stdout', 'w');
            $this->errorOutput = $errorOutput ?? fopen('php://stderr', 'w');

            return;
        }

        // Resolve log destination from parameter or environment
        $destination = $logDestination ?? (getenv('LOG_DESTINATION') ?: 'stderr');

        if ($destination === 'stderr' || $destination === '') {
            $this->output = defined('STDOUT') ? STDOUT : fopen('php://stdout', 'w');
            $this->errorOutput = defined('STDERR') ? STDERR : fopen('php://stderr', 'w');
        } else {
            $stream = self::openLogFile($destination);
            $this->output = $stream;
            $this->errorOutput = $stream;
        }
    }

    public function debug(string $message, array $context = []): void
    {
        $this->write('debug', $message, $context);
    }

    public function info(string $message, array $context = []): void
    {
        $this->write('info', $message, $context);
    }

    public function warn(string $message, array $context = []): void
    {
        $this->write('warn', $message, $context);
    }

    public function error(string $message, array $context = []): void
    {
        $this->write('error', $message, $context);
    }

    private function write(string $level, string $message, array $context): void
    {
        if (self::LEVELS[$level] < $this->minLevel) {
            return;
        }

        $entry = [
            'timestamp' => date('c'),
            'level' => $level,
            'service' => $this->service,
            'message' => $message,
        ];

        if (! empty($context)) {
            $entry['context'] = $this->sanitize($context);
        }

        $line = json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";

        $stream = in_array($level, ['warn', 'error']) ? $this->errorOutput : $this->output;
        fwrite($stream, $line);
    }

    /**
     * @return resource
     */
    private static function openLogFile(string $path)
    {
        $dir = dirname($path);
        if (! is_dir($dir)) {
            mkdir($dir, 0750, true);
        }

        $stream = fopen($path, 'a');
        if ($stream === false) {
            fwrite(STDERR, "WARNING: Cannot open log file {$path}, falling back to stderr\n");

            return defined('STDERR') ? STDERR : fopen('php://stderr', 'w');
        }

        // Restrict file permissions (owner read/write, group read)
        chmod($path, 0640);

        return $stream;
    }

    private function sanitize(array $data): array
    {
        $clean = [];

        foreach ($data as $key => $value) {
            if (is_string($key) && $this->isSensitiveKey($key)) {
                $clean[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $clean[$key] = $this->sanitize($value);
            } else {
                $clean[$key] = $value;
            }
        }

        return $clean;
    }

    private function isSensitiveKey(string $key): bool
    {
        $lower = strtolower($key);

        foreach (self::SENSITIVE_KEYS as $sensitive) {
            if (str_contains($lower, $sensitive)) {
                return true;
            }
        }

        return false;
    }
}
