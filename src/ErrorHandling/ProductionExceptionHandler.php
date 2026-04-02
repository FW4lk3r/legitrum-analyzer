<?php

namespace Legitrum\Analyzer\ErrorHandling;

use Legitrum\Analyzer\Logging\Logger;

class ProductionExceptionHandler
{
    private Logger $logger;

    private bool $isProduction;

    public function __construct(Logger $logger, bool $isProduction = false)
    {
        $this->logger = $logger;
        $this->isProduction = $isProduction;
    }

    public function register(): void
    {
        set_exception_handler([$this, 'handleException']);
    }

    public function handleException(\Throwable $e): void
    {
        $refId = substr(bin2hex(random_bytes(4)), 0, 8);

        $this->logger->error($e->getMessage(), [
            'ref_id' => $refId,
            'exception' => get_class($e),
            'code' => $e->getCode(),
            'file' => $this->isProduction ? basename($e->getFile()) : $e->getFile(),
            'line' => $e->getLine(),
        ]);

        if ($this->isProduction) {
            fwrite(STDERR, "FATAL: {$e->getMessage()} [ref:{$refId}]\n");
        } else {
            fwrite(STDERR, "FATAL: {$e->getMessage()} [ref:{$refId}]\n");
            fwrite(STDERR, $e->getTraceAsString() . "\n");
        }

        exit(1);
    }
}
