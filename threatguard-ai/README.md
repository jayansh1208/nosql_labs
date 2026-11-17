# ThreatGuard AI

ThreatGuard AI is a multi-tenant MongoDB-backed security intelligence platform implemented in a dedicated project directory, isolated from the existing coursework.

## Scope

This repo keeps the original course labs untouched. All project work for the application lives under the root-level `threatguard-ai` directory.

## Current phase

Phase 4A adds real local embeddings and tenant-scoped semantic retrieval for the knowledge base. It does not generate chatbot or LLM answers. Phase 3 remains the native Windows host scanner, its risk engine, JSON export workflow, scanner API endpoints, and dashboard integration.

## Default architecture

- MongoDB 7 on port 27030
- FastAPI backend on port 8000
- Streamlit frontend on port 8501
- Shared database: `threatguard`
- Local development tenant context only; no production authentication is implemented yet

## Database collections

The database initializes these collections:

- `organizations`
- `tenants`
- `users`
- `threats`
- `scan_results`
- `mitigations`
- `kb_documents`
- `kb_chunks`
- `chat_sessions`
- `audit_logs`
- `metrics_snapshots`

Each tenant-scoped record includes `org_id`, `tenant_id`, `created_at`, and `updated_at` where relevant.

## Schema validation

The validation layer enforces required fields, MongoDB types, exact threat lifecycle values, valid severity values, and tenant scoping. Invalid threat statuses are rejected at the database layer.

Threat lifecycle statuses must be exactly:

- `Anticipated`
- `Active`
- `Evolving`
- `Resolved`

## Index strategy

The initialization script creates the required indexes for tenant-scoped queries and lookup patterns, including unique indexes for high-value identifiers and composite indexes for tenant + status/time filtering.

## Tenant isolation design

All tenant-scoped repository operations enforce `org_id` and `tenant_id` server-side. Reads, updates, and deletes are limited to the supplied tenant context. Missing tenant or org context raises an error and cross-tenant access is rejected.

This is a development-only tenant context and not production authentication.

## Initialization commands

From the workspace root:

```bash
python .\threatguard-ai\backend\app\database\init_db.py
```

Or from the project root:

```bash
cd .\threatguard-ai
python .\backend\app\database\init_db.py
```

The script is safe to run repeatedly. It creates missing collections, applies validators, creates indexes, and verifies database readiness without destroying data.

## API endpoints

Available core endpoints:

- `POST /organizations`
- `GET /organizations`
- `POST /tenants`
- `GET /tenants`
- `POST /threats`
- `GET /threats`
- `GET /threats/{threat_id}`
- `PATCH /threats/{threat_id}/status`
- `POST /auth/register`
- `POST /auth/login`
- `GET /auth/me`
- `POST /scanner/scans`
- `GET /scanner/scans`
- `GET /scanner/scans/{scan_id}`
- `GET /scanner/scans/{scan_id}/summary`

Example request payload for a threat:

```json
{
  "org_id": "org-1",
  "tenant_id": "tenant-a",
  "threat_id": "thr-001",
  "title": "Privilege escalation attempt",
  "description": "Suspicious admin activity detected.",
  "severity": "high",
  "lifecycle_status": "Active",
  "source": "SIEM",
  "confidence": 0.91,
  "tags": ["identity", "admin"]
}
```

For development use, pass `org_id` and `tenant_id` explicitly in the request/route context. This is not an authentication mechanism.

## Test commands

Run the Phase 1 tests against the dedicated test database:

```bash
cd .\threatguard-ai
python -m pytest .\tests\test_phase1.py -q
```

## Windows scanner design

The Phase 3 CLI runs on the Windows host and uses read-only PowerShell queries for processes, network connections, startup entries, and Defender status. A collector failure is recorded as metadata; it never substitutes demo or sample findings. Raw process, network, and startup records are observations and are not themselves security findings. Findings are included only when a detector supplies them. Reports label injected/demo findings as `simulated` and host collection as `live`.

Each collector reports its name, status, number of items collected, error code/message when applicable, and scan timestamp. Overall completeness is `complete`, `partial`, or `failed`. When any collector has incomplete coverage, the report discloses that coverage and withholds severity and score. Defender access restrictions are reported as `permission_restricted` with Defender state `unknown`; the scanner does not elevate privileges.

Run from the project directory:

```powershell
python -m scanner.cli --limit 20
```

`--limit N` caps the total findings in the combined report, after deterministic concatenation in process, network, then startup order. The default is 20; zero is allowed and a negative value is rejected. Collector item counts remain independent of this report finding limit.

## Phase 4A knowledge base

The implementation reuses the existing `kb_documents` and `kb_chunks` collections and adds fields and tenant-scoped indexes through the existing schema initializer. The Phase 4A implementation was checked against the existing database before changes; both collections were empty. No existing records or MongoDB volumes are dropped.

The production embedding provider is `sentence-transformers/all-MiniLM-L6-v2`, using genuine model output with 384-dimensional unit-normalized vectors. It defaults to CPU, loads once per backend process, and batches input in groups of 32. The first embedding request downloads the model if it is not cached; subsequent loads use `EMBEDDING_CACHE_DIR`. Set `EMBEDDING_DEVICE=cuda` to request GPU acceleration when a compatible PyTorch/CUDA runtime is installed. There is no automatic fake-vector or keyword fallback.

Ingestion accepts PDF, UTF-8 TXT, and Markdown files up to `KB_MAX_UPLOAD_BYTES` (10 MiB by default). Text is normalized and chunked by character count using `KB_CHUNK_SIZE` and `KB_CHUNK_OVERLAP`. PDF chunks retain their source page. A tenant-scoped SHA-256 check detects duplicate content. Uploaded bytes are parsed as data and are never executed.

The local MongoDB retrieval path computes cosine similarity over the authenticated tenant's vectors and returns the top results with filenames, page numbers, chunk indexes, excerpts, and relevance scores. Atlas Vector Search is optional through `KB_ATLAS_VECTOR_SEARCH_ENABLED` and `KB_ATLAS_VECTOR_INDEX`. The Streamlit Knowledge Base page displays retrieved excerpts as source material; it clearly states that no generated answer is produced in this phase.

Authenticated API endpoints:

- `POST /knowledge/documents` (multipart field `file`)
- `GET /knowledge/documents`
- `GET /knowledge/documents/{document_id}`
- `DELETE /knowledge/documents/{document_id}`
- `POST /knowledge/search` with `{"query": "...", "top_k": 5}`

All organization and tenant filters come from the authenticated user context. Upload, search, list, and delete actions follow existing RBAC permissions and write relevant events to `audit_logs`.

The existing running Docker containers were left untouched. After reviewing this phase, rebuild the backend and frontend services from this directory to activate these source changes in the containers; the existing `mongo_data` volume is retained, and `embedding_cache` is a separate persistent cache volume.

## Phase 4B/4C AI analyst chat

The chatbot reuses the existing JWT/RBAC layer, `chat_sessions` collection, Phase 4A embedding provider and tenant-scoped semantic retrieval. The default provider is `ollama` at `http://localhost:11434`, with model `llama3.2:3b`; the application does not install, launch, download, or start Ollama automatically. The API and other pages still start when Ollama is unavailable. Chat requests then return a safe provider-unavailable response. OpenAI is optional and is used only when `AI_PROVIDER=openai` is explicitly selected and a key is configured.

Configure chat through `.env` (copy `.env.example`, then set only the provider you intend to use):

```dotenv
AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2:3b
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
AI_TEMPERATURE=0.2
AI_MAX_TOKENS=1000
AI_TIMEOUT_SECONDS=60
AI_HISTORY_WINDOW=8
AI_CONTEXT_MAX_CHARS=8000
AI_MAX_MESSAGE_CHARS=4000
AI_RATE_LIMIT_PER_MINUTE=10
CHAT_RAG_ENABLED=true
CHAT_RAG_TOP_K=5
CHAT_RAG_MIN_SIMILARITY=0.30
CHAT_SCANNER_CONTEXT_LIMIT=5
```

For local native Python, run Ollama separately and set `OLLAMA_BASE_URL=http://localhost:11434`. For the Docker backend to reach Ollama on the Windows host, set `OLLAMA_BASE_URL=http://host.docker.internal:11434`. Ollama remains outside default Compose startup. To use OpenAI, set `AI_PROVIDER=openai` and supply `OPENAI_API_KEY` in the local `.env`; keys are sent only to the OpenAI request header, are never logged or returned, and are never stored in MongoDB. The provider test endpoint makes a real request only when explicitly called. Automated tests use mocked providers and do not make paid calls.

For a separate local Ollama installation, install Ollama for the host OS, start its service manually, and install a model such as `llama3.2:3b` using Ollama's own model management. The app never starts Ollama or executes model-generated commands. CPU embeddings remain the default; the chatbot does not load an LLM model into the application process.

The analyst prompt treats retrieved documents and scanner records as untrusted evidence, rejects instructions embedded in those sources, prohibits host actions, and requires uncertainty to be explicit. Scanner context comes only from stored records matching the authenticated user's `org_id` and `tenant_id`; only stored finding descriptions and severity are passed, without raw command lines. Document citations are generated from retrieved chunks that pass `CHAT_RAG_MIN_SIMILARITY`; the answer's `[S#]` markers are checked against those actual citations. When retrieval finds no relevant source, the response clearly labels any explanation as general guidance. RAG can be globally disabled with `CHAT_RAG_ENABLED=false` or per request through the authenticated API.

Chat sessions are stored in the existing `chat_sessions` collection, scoped to organization, tenant, and owning user. Message content, timestamps, provider/model, citations, scanner references, and token usage are stored; credentials and full prompts are not added to audit records. Context sent to the provider is bounded by `AI_HISTORY_WINDOW` and `AI_CONTEXT_MAX_CHARS`, while each request is limited by `AI_MAX_MESSAGE_CHARS` and `AI_RATE_LIMIT_PER_MINUTE`.

Authenticated API endpoints:

- `POST /chat/sessions`
- `GET /chat/sessions?page=1&page_size=20`
- `GET /chat/sessions/{session_id}?message_offset=0&message_limit=50`
- `PATCH /chat/sessions/{session_id}` with `{"title": "..."}`
- `DELETE /chat/sessions/{session_id}`
- `POST /chat/sessions/{session_id}/messages` with `{"content": "...", "use_rag": true, "include_scanner_context": false}`
- `POST /chat/ask` with the same message fields and optional `session_id`
- `GET /chat/providers` (returns provider/model and a boolean key-configured flag only)
- `POST /chat/providers/test` (explicitly contacts the selected provider; never returns secrets)

The Streamlit Chatbot page supports login, conversation history, rename/delete, provider status/testing, example prompts, optional RAG, and explicit latest-scan context. It displays document citations and scanner evidence separately. Responses are not streamed in this phase; the interface shows a loading state while a bounded provider request completes.

Troubleshooting:

- `Ollama is unavailable`: start Ollama manually or explicitly configure OpenAI; no provider switch happens automatically.
- `The configured Ollama model is not available locally`: install the exact `OLLAMA_MODEL` on the host.
- `OpenAI rejected the configured API key`: check the local environment configuration; the key is not echoed in the error.
- No document citations: upload tenant-visible PDF/TXT/Markdown references, or lower `CHAT_RAG_MIN_SIMILARITY` with care.
- Docker's running backend/frontend images do not hot-reload source. After review, safely rebuild only those services from this directory with `docker compose up -d --build backend frontend`. This does not delete volumes; do not use `down -v`. Compose keeps Ollama outside default startup.

Phase 4B/4C tests use temporary MongoDB databases and mocked LLM providers. Run them with the full suite using `python -m pytest -q`; the separate Phase 4A real embedding test remains opt-in. No paid provider call is part of the suite.

Install backend dependencies from the project directory with `python -m pip install -r .\backend\requirements.txt`. Run regular tests with `python -m pytest -q`. The real model integration test is opt-in so the model is not downloaded on every test run:

```powershell
$env:THREATGUARD_RUN_EMBEDDING_INTEGRATION = "1"
python -m pytest .\tests\test_phase4a_knowledge.py -q
```

## Phase 0 validation

The startup layer continues to work as expected:

- MongoDB is available on `localhost:27030`
- FastAPI health endpoint returns `200`
- Streamlit frontend remains available on port `8501`
- The scanner runs as a native host-side workflow and can export JSON without affecting the running Docker containers

## Implementation notes

- New code remains inside `threatguard-ai` only.
- Course labs and root project files remain untouched.
- No MongoDB containers or volumes are recreated or deleted.
