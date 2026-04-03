<?php

namespace Legitrum\Analyzer;

use Legitrum\Analyzer\Auth\LegitruAuthClient;
use Legitrum\Analyzer\Chunker\ContentChunker;
use Legitrum\Analyzer\Reporter\FindingsReporter;
use Legitrum\Analyzer\Scanner\FileIndexer;
use Legitrum\Analyzer\Scanner\GrepSearch;
use Legitrum\Analyzer\Scanner\SnippetExtractor;
use Legitrum\Analyzer\Logging\Logger;
use Legitrum\Analyzer\Security\FileValidator;

class Analyzer
{
    private LegitruAuthClient $auth;

    private FileIndexer $indexer;

    private GrepSearch $grep;

    private SnippetExtractor $extractor;

    private ContentChunker $chunker;

    private FindingsReporter $reporter;

    private FileValidator $fileValidator;

    private Logger $logger;

    private float $startTime;

    public function __construct(
        string $token,
        private string $server,
        private string $assessmentId,
        private string $projectPath,
        string $logLevel = 'info',
    ) {
        $this->logger = new Logger($logLevel);
        $this->auth = new LegitruAuthClient($token, $server, $this->logger);
        $this->indexer = new FileIndexer();
        $this->grep = new GrepSearch($this->logger);
        $this->extractor = new SnippetExtractor();
        $this->chunker = new ContentChunker();
        $this->reporter = new FindingsReporter();
        $this->fileValidator = new FileValidator();
        $this->grep->setValidator($this->fileValidator);
        $this->startTime = microtime(true);
    }

    public function run(): void
    {
        $this->log('=== Legitrum Analyzer v1.0 ===');
        $this->log("Projecto: {$this->projectPath}");
        $this->log("Servidor: {$this->server}");

        // 1. Authenticate
        $this->log('A autenticar...');
        $this->auth->authenticate((int) $this->assessmentId);
        $this->log('Autenticado com sucesso.');

        // 2. Index all files
        $this->log('A indexar codebase...');
        $allFiles = $this->indexer->index($this->projectPath);
        $totalLines = array_sum(array_column($allFiles, 'lines'));
        $this->log(sprintf('Encontrados %d ficheiros — %s linhas de codigo', count($allFiles), number_format($totalLines)));

        if (empty($allFiles)) {
            $this->log('AVISO: Nenhum ficheiro encontrado em /repo. Verifica o volume mount.');

            return;
        }

        // Report progress
        $this->auth->reportProgress((int) $this->assessmentId, [
            'total_files' => count($allFiles),
            'total_lines' => $totalLines,
            'status' => 'indexing_complete',
        ]);

        // 3. Collect and send SBOM data
        $sbomFiles = [
            'composer.lock',
            'package-lock.json',
            'yarn.lock',
            'requirements.txt',
            'Pipfile.lock',
            'Gemfile.lock',
            'go.sum',
        ];

        $found = [];
        foreach ($sbomFiles as $file) {
            $path = $this->projectPath . DIRECTORY_SEPARATOR . $file;
            if (file_exists($path)) {
                $found[$file] = file_get_contents($path);
                $this->log("SBOM: encontrado {$file}");
            }
        }

        if (! empty($found)) {
            $this->auth->reportSbomFiles((int) $this->assessmentId, $found);
        }

        // 4. Get criteria from Legitrum (returns search_patterns per criterion)
        $this->log('A obter criterios...');
        $criteria = $this->auth->getCriteria((int) $this->assessmentId);
        $this->log(sprintf('A avaliar %d criterios', count($criteria)));

        if (empty($criteria)) {
            $this->log('AVISO: Nenhum criterio para avaliar.');

            return;
        }

        // 5. Process each criterion
        foreach ($criteria as $index => $criterion) {
            $num = $index + 1;
            $title = $criterion['title'] ?? 'Unknown';
            $criterionId = $criterion['id'];
            $this->log($this->reporter->formatProgress($num, count($criteria), $title));

            $patterns = $criterion['search_patterns'] ?? [];
            if (empty($patterns)) {
                $this->debug("  Sem search patterns — a enviar sem evidencia");
                $this->auth->reportEvidence((int) $this->assessmentId, $criterionId, [
                    'snippets' => [],
                    'files_searched' => count($allFiles),
                    'files_relevant' => 0,
                ]);

                continue;
            }

            // Find relevant files
            $relevantFiles = $this->grep->findRelevantFiles($allFiles, $patterns, $this->projectPath);

            if (empty($relevantFiles)) {
                $this->debug("  Sem ficheiros relevantes");
                $this->auth->reportEvidence((int) $this->assessmentId, $criterionId, [
                    'snippets' => [],
                    'files_searched' => count($allFiles),
                    'files_relevant' => 0,
                ]);

                continue;
            }

            $this->debug(sprintf('  %d ficheiros relevantes', count($relevantFiles)));

            // Extract complete functions/classes
            $snippets = [];
            foreach ($relevantFiles as $file) {
                $extracted = $this->extractor->extract(
                    $file['content'],
                    $file['path'],
                    $patterns,
                );
                $snippets = array_merge($snippets, $extracted);
            }

            $this->debug(sprintf('  %d snippets extraidos', count($snippets)));

            // Chunk into 40KB pieces and send each individually
            $chunks = $this->chunker->chunk($snippets);
            $chunksTotal = count($chunks);

            if ($chunksTotal === 0) {
                $this->auth->reportEvidence((int) $this->assessmentId, $criterionId, [
                    'snippets' => [],
                    'files_searched' => count($allFiles),
                    'files_relevant' => count($relevantFiles),
                ]);
            } else {
                foreach ($chunks as $chunkIndex => $chunkSnippets) {
                    $this->debug(sprintf('  A enviar chunk %d/%d (%d snippets)', $chunkIndex + 1, $chunksTotal, count($chunkSnippets)));

                    $this->auth->reportEvidence(
                        (int) $this->assessmentId,
                        $criterionId,
                        [
                            'snippets' => $chunkSnippets,
                            'files_searched' => count($allFiles),
                            'files_relevant' => count($relevantFiles),
                        ],
                        $chunkIndex,
                        $chunksTotal,
                    );

                    // Small delay between chunks
                    if ($chunkIndex < $chunksTotal - 1) {
                        usleep(500000);
                    }
                }
            }

            // Rate limit: 1.5s between criteria
            usleep(1500000);
        }

        // 6. Validation summary
        $validationSummary = $this->fileValidator->getSummary();
        if ($validationSummary['rejected'] > 0 || $validationSummary['warnings'] > 0) {
            $this->log(sprintf(
                'Validacao: %d ficheiros validados, %d rejeitados, %d avisos',
                $validationSummary['files_validated'],
                $validationSummary['rejected'],
                $validationSummary['warnings'],
            ));
        }

        // 7. Signal completion
        $duration = microtime(true) - $this->startTime;

        $this->auth->reportComplete((int) $this->assessmentId, [
            'total_files_analyzed' => count($allFiles),
            'total_lines_analyzed' => $totalLines,
            'duration_seconds' => (int) $duration,
        ]);

        $this->log($this->reporter->formatSummary(count($allFiles), $totalLines, count($criteria), $duration));
        $this->log("Ver resultados em: {$this->server}/assessments/{$this->assessmentId}");
    }

    private function log(string $message, array $context = []): void
    {
        $this->logger->info($message, $context);
    }

    private function debug(string $message, array $context = []): void
    {
        $this->logger->debug($message, $context);
    }
}
