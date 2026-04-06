<?php

namespace Legitrum\Analyzer;

use Legitrum\Analyzer\Auth\LegitruAuthClient;
use Legitrum\Analyzer\Chunker\ContentChunker;
use Legitrum\Analyzer\Notifier\WebhookNotifier;
use Legitrum\Analyzer\Reporter\FindingsReporter;
use Legitrum\Analyzer\Reporter\ReportGenerator;
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

    private ReportGenerator $reportGenerator;

    private Logger $logger;

    private float $startTime;

    private bool $noWait;

    private int $resultTimeout;

    private int $complianceThreshold;

    private ?string $reportOutput;

    private ?string $webhookUrl;

    public function __construct(
        string $token,
        private string $server,
        private string $assessmentId,
        private string $projectPath,
        string $logLevel = 'info',
        bool $noWait = false,
        int $resultTimeout = 300,
        int $complianceThreshold = 100,
        ?string $reportOutput = null,
        ?string $webhookUrl = null,
    ) {
        $this->logger = new Logger($logLevel);
        $this->auth = new LegitruAuthClient($token, $server, $this->logger);
        $this->indexer = new FileIndexer();
        $this->grep = new GrepSearch($this->logger);
        $this->extractor = new SnippetExtractor();
        $this->chunker = new ContentChunker();
        $this->reporter = new FindingsReporter();
        $this->fileValidator = new FileValidator();
        $this->reportGenerator = new ReportGenerator();
        $this->grep->setValidator($this->fileValidator);
        $this->startTime = microtime(true);
        $this->noWait = $noWait;
        $this->resultTimeout = $resultTimeout;
        $this->complianceThreshold = $complianceThreshold;
        $this->reportOutput = $reportOutput;
        $this->webhookUrl = $webhookUrl;
    }

    public function getAuth(): LegitruAuthClient
    {
        return $this->auth;
    }

    public function run(): int
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

            return 0;
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

            return 0;
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

        $completionConfirmed = true;
        try {
            $this->auth->reportComplete((int) $this->assessmentId, [
                'total_files_analyzed' => count($allFiles),
                'total_lines_analyzed' => $totalLines,
                'duration_seconds' => (int) $duration,
            ]);
        } catch (\Exception $e) {
            $completionConfirmed = false;
        }

        $this->log($this->reporter->formatSummary(count($allFiles), $totalLines, count($criteria), $duration));

        // 8. Poll for results (unless no-wait mode)
        $serverResults = null;
        if (! $this->noWait) {
            $serverResults = $this->pollResults((int) $this->assessmentId);
        } else {
            $this->log('Modo no-wait activo — a saltar polling de resultados.');
        }

        // 9. Display results summary
        $resultsUrl = "{$this->server}/assessments/{$this->assessmentId}";
        $this->log($this->reporter->formatResults($serverResults, $resultsUrl, $this->complianceThreshold));

        // 10. Generate report
        $sbomSubmitted = ! empty($found);
        $scanSummary = [
            'total_files_analyzed' => count($allFiles),
            'total_lines_analyzed' => $totalLines,
            'criteria_evaluated' => count($criteria),
            'duration_seconds' => (int) $duration,
            'sbom_submitted' => $sbomSubmitted,
            'files_rejected' => $validationSummary['rejected'],
            'files_warned' => $validationSummary['warnings'],
        ];

        $report = $this->reportGenerator->generate(
            (int) $this->assessmentId,
            $this->server,
            $scanSummary,
            $serverResults,
            $completionConfirmed,
        );

        // 11. Output report
        if ($this->reportOutput !== null) {
            $this->reportGenerator->writeToFile($report, $this->reportOutput);
            $this->log("Relatorio escrito em: {$this->reportOutput}");
        } else {
            fwrite(STDOUT, $this->reportGenerator->toJson($report) . "\n");
        }

        // 12. Webhook notification
        if ($this->webhookUrl !== null) {
            $notifier = new WebhookNotifier($this->logger, $this->auth);
            $notifier->send($this->webhookUrl, $report);
        }

        // 13. Determine exit code
        return $this->reportGenerator->determineExitCode(
            $serverResults,
            $this->complianceThreshold,
            $this->noWait,
        );
    }

    private function pollResults(int $assessmentId): ?array
    {
        $interval = 5.0;
        $elapsed = 0.0;
        $attempts = 0;
        $maxAttempts = 20;

        $this->log('A aguardar resultados do servidor...');

        while ($elapsed < $this->resultTimeout && $attempts < $maxAttempts) {
            $attempts++;
            usleep((int) ($interval * 1_000_000));
            $elapsed += $interval;

            $this->debug(sprintf('Polling tentativa %d (%.0fs decorridos)', $attempts, $elapsed));

            $result = $this->auth->getResults($assessmentId);

            if ($result === null) {
                $this->log('Endpoint de resultados nao disponivel (backward compatibility) — a continuar sem resultados.');

                return null;
            }

            $status = $result['status'] ?? '';

            if ($status === 'completed') {
                $this->log('Resultados recebidos do servidor.');

                return $result;
            }

            if ($status === 'failed') {
                $this->log('Pipeline AI falhou no servidor: ' . ($result['reason'] ?? 'razao desconhecida'));

                return $result;
            }

            // Handle 429 with Retry-After
            if (isset($result['_retry_after']) && $result['_retry_after'] > 0) {
                $interval = (float) $result['_retry_after'];
            } else {
                $interval = min($interval * 1.5, 60.0);
            }
        }

        $this->log(sprintf('Timeout no polling de resultados apos %.0f segundos (%d tentativas)', $elapsed, $attempts));

        return null;
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
