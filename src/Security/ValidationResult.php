<?php

namespace Legitrum\Analyzer\Security;

class ValidationResult
{
    public function __construct(
        public readonly bool $valid,
        public readonly bool $rejected,
        public readonly bool $warning,
        public readonly string $reason,
    ) {}

    public static function pass(): self
    {
        return new self(true, false, false, '');
    }

    public static function reject(string $reason): self
    {
        return new self(false, true, false, $reason);
    }

    public static function warn(string $reason): self
    {
        return new self(true, false, true, $reason);
    }
}
