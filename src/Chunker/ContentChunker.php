<?php

namespace Legitrum\Analyzer\Chunker;

class ContentChunker
{
    private int $maxSize;

    public function __construct(int $maxSize = 40000)
    {
        $this->maxSize = $maxSize;
    }

    public function chunk(array $snippets): array
    {
        $chunks = [];
        $current = [];
        $currentSize = 0;

        foreach ($snippets as $snippet) {
            $snippetSize = strlen($snippet['snippet']);

            // Single snippet exceeds limit — add alone
            if ($snippetSize > $this->maxSize) {
                if (! empty($current)) {
                    $chunks[] = $current;
                    $current = [];
                    $currentSize = 0;
                }
                // Truncate if necessary
                $snippet['snippet'] = mb_substr($snippet['snippet'], 0, $this->maxSize);
                $chunks[] = [$snippet];

                continue;
            }

            // Adding would exceed limit — start new chunk
            if ($currentSize + $snippetSize > $this->maxSize && ! empty($current)) {
                $chunks[] = $current;
                $current = [];
                $currentSize = 0;
            }

            $current[] = $snippet;
            $currentSize += $snippetSize;
        }

        if (! empty($current)) {
            $chunks[] = $current;
        }

        return $chunks;
    }
}
