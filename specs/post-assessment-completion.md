# spec: post-assessment-completion

## Contexto

Quando o analyzer termina a execucao (`Analyzer::run()` completa), o fluxo actual e minimo: envia `reportComplete()` ao servidor e imprime um resumo no CLI. Nao ha processamento local de resultados, nenhuma notificacao ao utilizador, e o exit code e sempre 0 (excepto erros fatais). Para integracoes CI/CD, audit trails, e visibilidade operacional, o analyzer precisa de um fluxo pos-conclusao robusto que recolha resultados, produza artefactos uteis, e sinalize o outcome de forma programatica.

## Objetivo

Definir o fluxo completo que ocorre apos o analyzer concluir a submissao de evidencias — desde obter resultados do servidor ate gerar relatorios locais, emitir exit codes semanticos, e notificar stakeholders.

## Comportamento esperado

### 1. Obter resultados do servidor (Result Polling)

- Apos `reportComplete()`, o analyzer faz polling a um novo endpoint `GET /api/analyzer/results/{assessmentId}` para obter o resultado da avaliacao AI
- O servidor pode demorar a processar (pipeline AI), por isso o analyzer implementa polling com backoff:
  - Intervalo inicial: 5 segundos
  - Backoff multiplicativo: x1.5 por tentativa
  - Timeout maximo de polling: 5 minutos (configuravel via `RESULT_TIMEOUT` env var)
  - Maximo 20 tentativas
- O endpoint retorna um de tres estados:
  - `processing` — AI ainda a avaliar, continuar polling
  - `completed` — resultados prontos, payload inclui resultados por criterio
  - `failed` — pipeline AI falhou, payload inclui razao
- Se o timeout expirar sem resultado, o analyzer loga um warning e continua para a geracao de relatorio parcial (sem scores AI)

### 2. Estrutura dos resultados esperados do servidor

```json
{
  "status": "completed",
  "assessment_id": 123,
  "completed_at": "2026-04-07T14:30:00Z",
  "results": {
    "overall_score": 78,
    "overall_status": "partially_compliant",
    "criteria": [
      {
        "id": 45,
        "title": "A06:2021 - Vulnerable Components",
        "status": "compliant|non_compliant|partially_compliant|not_applicable",
        "score": 85,
        "findings": ["Evidence of dependency scanning found in CI pipeline"],
        "recommendations": ["Add SBOM generation to release process"]
      }
    ]
  },
  "metadata": {
    "ai_model_version": "1.x",
    "evaluation_duration_seconds": 30
  }
}
```

### 3. Geracao de relatorio local (Report Generation)

Apos obter resultados (ou apos timeout), gerar um relatorio local:

- **Formato**: JSON estruturado, escrito em `stdout` ou ficheiro (configuravel via `REPORT_OUTPUT` env var)
- **Ficheiro default**: nao gera ficheiro — output vai para `stdout` como JSON apos o resumo humano
- **Se `REPORT_OUTPUT` definido**: escreve para o path indicado (e.g., `./legitrum-report.json`)
- **Permissoes do ficheiro**: 0640 (owner read/write, group read, others none)

Estrutura do relatorio local:

```json
{
  "version": "1.0",
  "generated_at": "2026-04-07T14:30:05Z",
  "assessment_id": 123,
  "server": "https://app.legitrum.pt",
  "analyzer_version": "1.0",
  "scan_summary": {
    "total_files_analyzed": 150,
    "total_lines_analyzed": 25000,
    "criteria_evaluated": 12,
    "duration_seconds": 45,
    "sbom_submitted": true,
    "files_rejected": 2,
    "files_warned": 1
  },
  "results": {
    "available": true,
    "overall_score": 78,
    "overall_status": "partially_compliant",
    "criteria": [...]
  },
  "results_url": "https://app.legitrum.pt/assessments/123"
}
```

Se os resultados nao estiverem disponiveis (timeout ou falha):

```json
{
  "results": {
    "available": false,
    "reason": "timeout|server_error",
    "message": "Results not available yet. Check https://app.legitrum.pt/assessments/123"
  }
}
```

### 4. Exit codes semanticos

O analyzer deve sair com exit codes que CI/CD pipelines possam interpretar:

| Exit Code | Significado | Quando |
|-----------|------------|--------|
| 0 | Sucesso — assessment compliant | Score >= threshold (default 100) |
| 1 | Erro fatal | Falha de autenticacao, rede, configuracao |
| 2 | Assessment nao compliant | Score < threshold |
| 3 | Resultados indisponiveis | Timeout no polling ou falha do pipeline AI |

- O threshold e configuravel via `COMPLIANCE_THRESHOLD` env var (default: `100`, aceita 0-100)
- Se `COMPLIANCE_THRESHOLD=0`, exit code 2 nunca e emitido (modo informativo)
- Se nao houver resultados disponives, exit code 3 (a nao ser que `--no-wait` flag esteja activa, caso em que sai com 0)

### 5. Modo no-wait (skip polling)

- Activado via `NO_WAIT=1` env var
- Salta o polling de resultados completamente
- Gera relatorio parcial (sem scores AI)
- Sai sempre com exit code 0 (desde que a submissao tenha sido bem-sucedida)
- Util para pipelines que so querem submeter evidencias sem bloquear

### 6. Resumo CLI melhorado

Alem do resumo actual, acrescentar informacao de resultados quando disponivel:

```
=== Analise concluida ===
Ficheiros analisados: 150
Linhas de codigo: 25,000
Criterios avaliados: 12
Duracao: 1.5 min

=== Resultados ===
Score global: 78/100 (partially_compliant)
  [PASS] A05:2021 - Security Misconfiguration (92/100)
  [WARN] A06:2021 - Vulnerable Components (65/100)
  [FAIL] A01:2021 - Broken Access Control (45/100)

Ver detalhes em: https://app.legitrum.pt/assessments/123
```

Se resultados nao disponiveis:

```
=== Analise concluida ===
...
Resultados: a processar no servidor (timeout apos 5 min)
Ver resultados em: https://app.legitrum.pt/assessments/123
```

### 7. Notificacoes via webhook (opcional)

- Activado via `WEBHOOK_URL` env var
- Envia POST request para o URL configurado com o relatorio JSON como body
- Headers: `Content-Type: application/json`, `User-Agent: Legitrum-Analyzer/1.0`
- Nao inclui token de autenticacao no webhook (seguranca)
- Timeout: 10 segundos
- Sem retries — loga warning em caso de falha
- URL validado contra o mesmo allowlist de `ALLOWED_SERVERS` (prevencao SSRF)
- Util para integrar com Slack incoming webhooks, Teams, PagerDuty, etc.

## Edge cases

- **Servidor retorna `processing` indefinidamente**: timeout apos 5 minutos, gera relatorio parcial, exit code 3
- **Servidor retorna `failed`**: loga o erro, gera relatorio com `results.available = false` e `reason = "server_error"`, exit code 3
- **Endpoint de resultados nao existe (404)**: o servidor pode nao ter esta feature ainda — tratar como timeout graciosamente, loga warning, exit code 0 com relatorio parcial (backward compatibility)
- **`REPORT_OUTPUT` aponta para directorio sem permissoes de escrita**: falha com exit code 1 e mensagem clara antes de tentar escrever
- **`REPORT_OUTPUT` path traversal**: validar com `realpath()` que o path resolvido nao sai do directorio de trabalho ou `/tmp`
- **`COMPLIANCE_THRESHOLD` com valor invalido**: falha com exit code 1 e mensagem de validacao
- **`WEBHOOK_URL` com URL invalido ou fora do allowlist**: loga warning e salta notificacao (nao bloqueia)
- **Resultados com criterios que o analyzer nao submeteu**: ignorar criterios extra no relatorio (servidor pode ter criterios avaliados manualmente)
- **Nenhum criterio avaliado** (`criteria` vazio): relatorio gerado normalmente com arrays vazios, exit code depende do score (que sera 0 ou n/a)
- **`reportComplete()` falhou apos 3 retries**: relatorio local gerado na mesma com dados do scan, mas `results.available = false` com `reason = "completion_not_confirmed"`

## API

### Novo endpoint (servidor — contrato apenas, implementacao e do servidor)

#### GET /api/analyzer/results/{assessmentId}

**Server validations:**

| Check | Error Code | Response |
|-------|-----------|----------|
| Session is authenticated | 401 | `unauthenticated` |
| Assessment exists | 404 | `assessment not found` |

**Success response (200):** Objecto JSON com `status` (`processing`, `completed`, `failed`) e `results` quando `completed`.

**Client-side handling:**

| Status | Accao |
|--------|------|
| `processing` | Continuar polling |
| `completed` | Extrair resultados, parar polling |
| `failed` | Logar razao, parar polling |

**Error recovery:**

| Scenario | Strategy |
|----------|---------|
| 401/403 | Parar polling, logar erro |
| 404 | Tratar como feature nao disponivel (backward compat), parar com warning |
| 429 | Respeitar `Retry-After` header, duplicar intervalo |
| 5xx | Continuar polling (servidor pode estar a recuperar) |
| Connection failure | Continuar polling ate timeout |

### Novo endpoint (webhook — POST para URL externo)

Corpo identico ao relatorio JSON local. Nao requer autenticacao no payload.

## Ficheiros a modificar/criar

| Ficheiro | Accao | Descricao |
|----------|------|-----------|
| `src/Analyzer.php` | Modificar | Adicionar fluxo pos-conclusao apos `reportComplete()` |
| `src/Auth/LegitruAuthClient.php` | Modificar | Adicionar metodo `getResults(int $assessmentId): array` |
| `src/Reporter/FindingsReporter.php` | Modificar | Adicionar `formatResults()` e `formatReport()` |
| `src/Reporter/ReportGenerator.php` | Criar | Classe dedicada a construir o relatorio JSON |
| `src/Notifier/WebhookNotifier.php` | Criar | Classe para enviar notificacoes via webhook |
| `run.php` | Modificar | Ler novas env vars, passar ao Analyzer, processar exit code |
| `docs/SERVER_VALIDATION_CONTRACT.md` | Modificar | Documentar novo endpoint de resultados |
| `tests/Reporter/ReportGeneratorTest.php` | Criar | Testes para geracao de relatorio |
| `tests/Notifier/WebhookNotifierTest.php` | Criar | Testes para webhook |
| `tests/Integration/ResultPollingTest.php` | Criar | Testes para polling com mock |

## Variaveis de ambiente novas

| Variavel | Tipo | Default | Descricao |
|----------|------|---------|-----------|
| `RESULT_TIMEOUT` | int (segundos) | `300` | Timeout maximo para polling de resultados |
| `NO_WAIT` | bool (`0`/`1`) | `0` | Salta polling, sai imediatamente apos submissao |
| `REPORT_OUTPUT` | string (path) | (nenhum) | Path para ficheiro de relatorio. Se omitido, JSON vai para stdout |
| `COMPLIANCE_THRESHOLD` | int (0-100) | `100` | Score minimo para exit code 0 |
| `WEBHOOK_URL` | string (URL) | (nenhum) | URL para notificacao POST apos conclusao |

## O que NAO implementar agora

- **Notificacoes por email**: complexidade de configuracao SMTP desnecessaria num CLI tool dockerizado. O webhook cobre este caso via integracao com servicos externos.
- **Relatorio HTML/PDF**: o JSON e consumivel por qualquer ferramenta. Relatorios visuais sao responsabilidade do servidor web.
- **Armazenamento local persistente de historico**: o analyzer e stateless por design. Historico vive no servidor.
- **Dashboard ou UI**: fora do scope deste componente CLI.
- **Comparacao com assessments anteriores (delta/diff)**: feature do servidor, nao do analyzer.
- **Upload automatico do relatorio para cloud storage**: scope creep. O webhook ou pipe do stdout cobrem este caso.
- **Notificacoes push (mobile)**: fora do scope.
- **Retry do polling apos timeout**: se o timeout expirar, o utilizador pode consultar o servidor manualmente. Nao re-tentar automaticamente.

## Criterios de aceitacao

- [ ] Apos `reportComplete()`, o analyzer faz polling a `GET /api/analyzer/results/{assessmentId}` com backoff exponencial ate obter resultados ou timeout
- [ ] Com `NO_WAIT=1`, o polling e saltado e o analyzer sai imediatamente apos submissao bem-sucedida
- [ ] O relatorio JSON inclui scan summary, resultados (quando disponiveis), e URL do assessment
- [ ] Com `REPORT_OUTPUT` definido, o relatorio e escrito para o ficheiro indicado com permissoes 0640
- [ ] Sem `REPORT_OUTPUT`, o relatorio JSON e escrito para stdout (separado do log que vai para stderr)
- [ ] Exit code 0 quando score >= `COMPLIANCE_THRESHOLD`
- [ ] Exit code 2 quando score < `COMPLIANCE_THRESHOLD`
- [ ] Exit code 3 quando resultados indisponiveis (timeout ou falha) e `NO_WAIT` nao esta activo
- [ ] `COMPLIANCE_THRESHOLD` aceita valores 0-100, falha com exit code 1 para valores invalidos
- [ ] Com `WEBHOOK_URL` definido, envia POST com relatorio JSON para o URL
- [ ] `WEBHOOK_URL` e validado contra o allowlist existente em `ALLOWED_SERVERS`
- [ ] Webhook falha silenciosamente (warning log) sem bloquear o exit do analyzer
- [ ] Endpoint de resultados 404 e tratado como backward-compatible (warning, nao erro fatal)
- [ ] Resumo CLI mostra scores por criterio quando resultados disponiveis
- [ ] Todas as novas env vars sao documentadas no `.env.example`
- [ ] Path do `REPORT_OUTPUT` e validado contra path traversal antes de escrita
- [ ] Novos metodos em `LegitruAuthClient` seguem o padrao existente de error handling e logging
- [ ] Testes unitarios cobrem: geracao de relatorio, polling states, exit code logic, webhook dispatch, edge cases de timeout
