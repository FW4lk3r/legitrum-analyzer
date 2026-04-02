# Server-Side Validation Contract

This document describes the expected server-side behavior for each API endpoint the analyzer communicates with. The Legitrum server is the authority for all business logic validation.

## Endpoints

### POST /api/analyzer/authenticate

**Request:**
```json
{
  "assessment_id": 123
}
```

**Server validations:**
| Check | Error Code | Response |
|-------|-----------|----------|
| Bearer token is valid and not expired | 401 | `invalid_or_expired_token` |
| Assessment exists | 404 | `assessment not found` |
| Assessment is active (not archived/completed) | 422 | `assessment is not active` |
| Token owner has permission to analyze this assessment | 403 | `access_denied` |

**Success response (200):** Assessment metadata (title, criteria count, configuration).

---

### GET /api/analyzer/criteria/{assessmentId}

**Server validations:**
| Check | Error Code | Response |
|-------|-----------|----------|
| Session is authenticated for this assessment | 401 | `unauthenticated` |
| Assessment exists | 404 | `assessment not found` |
| Assessment has criteria assigned | 200 | Returns empty array `[]` |

**Success response (200):** Array of criteria objects, each containing `id`, `title`, and `search_patterns`.

---

### POST /api/analyzer/evidence

**Request:**
```json
{
  "assessment_id": 123,
  "criterion_id": 45,
  "snippets": [...],
  "chunk_index": 0,
  "chunks_total": 3,
  "files_searched": 100,
  "files_relevant": 5
}
```

**Server validations:**
| Check | Error Code | Response |
|-------|-----------|----------|
| Session is authenticated | 401 | `unauthenticated` |
| `criterion_id` belongs to the assessment | 404 | `criterion not found` |
| Payload is well-formed JSON | 422 | Validation error details |
| Snippet content is within size limits | 422 | `payload too large` |
| Rate limit not exceeded | 429 | `too many requests` |

**Success response (200):** Confirmation with stored evidence ID.

---

### POST /api/analyzer/sbom

**Request:**
```json
{
  "assessment_id": 123,
  "files": {
    "composer.lock": "...",
    "package-lock.json": "..."
  }
}
```

**Server validations:**
| Check | Error Code | Response |
|-------|-----------|----------|
| Session is authenticated | 401 | `unauthenticated` |
| Assessment exists | 404 | `assessment not found` |
| Files are parseable dependency formats | 422 | Validation error |
| Total payload within limits | 413 | `payload too large` |

**Success response (200):** Confirmation.

---

### POST /api/analyzer/status/{assessmentId}

**Request:** Progress data (total_files, total_lines, status).

**Server validations:**
| Check | Error Code | Response |
|-------|-----------|----------|
| Session is authenticated | 401 | `unauthenticated` |
| Assessment exists | 404 | `assessment not found` |

**Success response (200):** Acknowledgement. Non-critical — analyzer continues on failure.

---

### POST /api/analyzer/complete

**Request:**
```json
{
  "assessment_id": 123,
  "summary": {
    "total_files_analyzed": 150,
    "total_lines_analyzed": 25000,
    "duration_seconds": 45
  }
}
```

**Server validations:**
| Check | Error Code | Response |
|-------|-----------|----------|
| Session is authenticated | 401 | `unauthenticated` |
| Assessment exists | 404 | `assessment not found` |
| All expected criteria have evidence submitted | 200 | Warning in response body |

**Success response (200):** Triggers server-side AI evaluation pipeline.

## Client-Side Response Handling

The analyzer validates all server responses:

- JSON responses are decoded and type-checked (must be arrays)
- Non-JSON or malformed responses are logged and raise `RuntimeException`
- 4xx errors are logged with structured context (status, reason, assessment ID)
- Connection failures trigger retries with exponential backoff (evidence, completion)
- Tokens are never included in error logs (only first 8 chars as prefix)

## Error Recovery

| Endpoint | Retry Strategy | On Final Failure |
|----------|---------------|-----------------|
| authenticate | No retry | Fatal — exits |
| getCriteria | No retry | Fatal — exits |
| reportEvidence | 3 attempts, exponential backoff | Warn + skip criterion |
| reportSbomFiles | No retry | Warn + continue |
| reportProgress | No retry | Silent + continue |
| reportComplete | 3 attempts, 2s delay | Warn + exit normally |
