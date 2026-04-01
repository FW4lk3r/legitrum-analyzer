<?php

namespace Legitrum\Analyzer\Scanner;

class SnippetExtractor
{
    public function extract(string $content, string $filePath, array $patterns): array
    {
        $snippets = [];
        $lines = explode("\n", $content);
        $totalLines = count($lines);

        foreach ($patterns as $pattern) {
            foreach ($lines as $lineNum => $line) {
                if (stripos($line, $pattern) === false) {
                    continue;
                }

                $blockStart = $this->findBlockStart($lines, $lineNum);
                $blockEnd = $this->findBlockEnd($lines, $lineNum, $totalLines);

                $snippet = implode("\n", array_slice($lines, $blockStart, $blockEnd - $blockStart + 1));

                $hash = md5($snippet);
                if (isset($snippets[$hash])) {
                    continue;
                }

                $snippets[$hash] = [
                    'file_path' => $filePath,
                    'line_start' => $blockStart + 1,
                    'line_end' => $blockEnd + 1,
                    'snippet' => $snippet,
                    'pattern_hit' => $pattern,
                ];
            }
        }

        return array_values($snippets);
    }

    private function findBlockStart(array $lines, int $lineNum): int
    {
        $start = max(0, $lineNum - 30);

        for ($i = $lineNum; $i >= $start; $i--) {
            $line = trim($lines[$i]);

            // PHP
            if (preg_match('/^(public|private|protected|static|function|class|abstract|trait|interface|enum|readonly)/', $line)) {
                return $i;
            }
            // TypeScript/JavaScript
            if (preg_match('/^(export|const|let|var|function|class|async|interface|type|enum)/', $line)) {
                return $i;
            }
            // Python
            if (preg_match('/^(def |class |async def |@)/', $line)) {
                return $i;
            }
            // Go
            if (preg_match('/^(func |type )/', $line)) {
                return $i;
            }
            // Ruby
            if (preg_match('/^(def |class |module )/', $line)) {
                return $i;
            }
        }

        return max(0, $lineNum - 5);
    }

    private function findBlockEnd(array $lines, int $lineNum, int $totalLines): int
    {
        // Try to find matching closing brace
        $braceCount = 0;
        $foundOpen = false;

        for ($i = $lineNum; $i < min($totalLines, $lineNum + 80); $i++) {
            $line = $lines[$i];
            $braceCount += substr_count($line, '{') - substr_count($line, '}');

            if (substr_count($line, '{') > 0) {
                $foundOpen = true;
            }

            if ($foundOpen && $braceCount <= 0) {
                return $i;
            }
        }

        return min($totalLines - 1, $lineNum + 50);
    }
}
