import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

APP_ENV = os.getenv("APP_ENV", "development")
APP_NAME = os.getenv("APP_NAME", "ThreatGuard AI")

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27030")
MONGO_DB = os.getenv("MONGO_DB", "threatguard")
MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_PORT = int(os.getenv("MONGO_PORT", "27030"))

FASTAPI_HOST = os.getenv("FASTAPI_HOST", "0.0.0.0")
FASTAPI_PORT = int(os.getenv("FASTAPI_PORT", "8000"))

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "").strip()
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRY_MINUTES = int(os.getenv("JWT_EXPIRY_MINUTES", "60"))

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")
STREAMLIT_SERVER_PORT = int(os.getenv("STREAMLIT_SERVER_PORT", "8501"))

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()

AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama").strip().lower()
AI_TEMPERATURE = float(os.getenv("AI_TEMPERATURE", "0.2"))
AI_MAX_TOKENS = int(os.getenv("AI_MAX_TOKENS", "1000"))
AI_TIMEOUT_SECONDS = float(os.getenv("AI_TIMEOUT_SECONDS", "60"))
AI_HISTORY_WINDOW = int(os.getenv("AI_HISTORY_WINDOW", "8"))
AI_CONTEXT_MAX_CHARS = int(os.getenv("AI_CONTEXT_MAX_CHARS", "8000"))
AI_MAX_MESSAGE_CHARS = int(os.getenv("AI_MAX_MESSAGE_CHARS", "4000"))
AI_RATE_LIMIT_PER_MINUTE = int(os.getenv("AI_RATE_LIMIT_PER_MINUTE", "10"))
CHAT_RAG_ENABLED = os.getenv("CHAT_RAG_ENABLED", "true").lower() == "true"
CHAT_RAG_TOP_K = int(os.getenv("CHAT_RAG_TOP_K", "5"))
CHAT_RAG_MIN_SIMILARITY = float(os.getenv("CHAT_RAG_MIN_SIMILARITY", "0.30"))
CHAT_SCANNER_CONTEXT_LIMIT = int(os.getenv("CHAT_SCANNER_CONTEXT_LIMIT", "5"))

EMBEDDING_PROVIDER = os.getenv("EMBEDDING_PROVIDER", "sentence_transformers")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
EMBEDDING_DEVICE = os.getenv("EMBEDDING_DEVICE", "cpu")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
EMBEDDING_CACHE_DIR = os.getenv("EMBEDDING_CACHE_DIR", str(PROJECT_ROOT / ".cache" / "models"))
KB_MAX_UPLOAD_BYTES = int(os.getenv("KB_MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))
KB_CHUNK_SIZE = int(os.getenv("KB_CHUNK_SIZE", "1000"))
KB_CHUNK_OVERLAP = int(os.getenv("KB_CHUNK_OVERLAP", "150"))
KB_RETRIEVAL_TOP_K = int(os.getenv("KB_RETRIEVAL_TOP_K", "5"))
KB_MAX_QUERY_CHARS = int(os.getenv("KB_MAX_QUERY_CHARS", "1000"))
KB_ATLAS_VECTOR_SEARCH_ENABLED = os.getenv("KB_ATLAS_VECTOR_SEARCH_ENABLED", "false").lower() == "true"
KB_ATLAS_VECTOR_INDEX = os.getenv("KB_ATLAS_VECTOR_INDEX", "kb_chunks_vector")
