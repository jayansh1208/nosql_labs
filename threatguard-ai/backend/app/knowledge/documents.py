from __future__ import annotations

import hashlib
import io
import re
import unicodedata
from dataclasses import dataclass
from pathlib import PurePath

from pypdf import PdfReader


SUPPORTED_TYPES = {".pdf": "pdf", ".txt": "txt", ".md": "markdown", ".markdown": "markdown"}


@dataclass(frozen=True)
class TextChunk:
    text: str
    chunk_index: int
    page_number: int | None = None


def safe_filename(filename: str) -> str:
    cleaned = filename.replace("\\", "/").split("/")[-1].strip()
    if not cleaned or cleaned in {".", ".."}:
        raise ValueError("A valid filename is required.")
    return cleaned


def sha256_content(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).replace("\x00", "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [re.sub(r"[\t\f\v ]+", " ", line).strip() for line in text.split("\n")]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def extract_document(filename: str, data: bytes) -> tuple[str, list[tuple[int | None, str]]]:
    name = safe_filename(filename)
    extension = PurePath(name).suffix.lower()
    file_type = SUPPORTED_TYPES.get(extension)
    if file_type is None:
        raise ValueError("Unsupported file type. Upload a PDF, TXT, or Markdown file.")
    if not data:
        raise ValueError("The uploaded document is empty.")

    if file_type == "pdf":
        try:
            reader = PdfReader(io.BytesIO(data), strict=True)
            if reader.is_encrypted:
                raise ValueError("Encrypted PDFs are not supported.")
            pages = [(index + 1, normalize_text(page.extract_text() or "")) for index, page in enumerate(reader.pages)]
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError("The PDF could not be read.") from exc
    else:
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("Text documents must use UTF-8 encoding.") from exc
        pages = [(None, normalize_text(text))]

    pages = [(page, text) for page, text in pages if text]
    if not pages:
        raise ValueError("No extractable text was found in the document.")
    return file_type, pages


def chunk_pages(pages: list[tuple[int | None, str]], *, chunk_size: int, overlap: int) -> list[TextChunk]:
    if chunk_size <= 0:
        raise ValueError("Chunk size must be greater than zero.")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("Chunk overlap must be non-negative and smaller than chunk size.")
    chunks: list[TextChunk] = []
    for page_number, text in pages:
        start = 0
        while start < len(text):
            end = min(start + chunk_size, len(text))
            if end < len(text):
                boundary = text.rfind(" ", start + int(chunk_size * 0.7), end)
                if boundary > start:
                    end = boundary
            piece = text[start:end].strip()
            if piece:
                chunks.append(TextChunk(piece, len(chunks), page_number))
            if end >= len(text):
                break
            start = max(start + 1, end - overlap)
            while start < len(text) and text[start].isspace():
                start += 1
    return chunks
