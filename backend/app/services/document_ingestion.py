import io
import os
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple

from fastapi import UploadFile

try:
    from pypdf import PdfReader
except Exception:  # pragma: no cover - optional dependency at runtime
    PdfReader = None

try:
    from docx import Document
except Exception:  # pragma: no cover - optional dependency at runtime
    Document = None


TEXT_EXTENSIONS = {
    ".txt",
    ".md",
    ".markdown",
    ".rst",
    ".adoc",
    ".csv",
    ".log",
    ".json",
    ".yaml",
    ".yml",
}
SUPPORTED_EXTENSIONS = TEXT_EXTENSIONS | {".pdf", ".docx"}
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024


def _read_text_bytes(raw_bytes: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ValueError("Could not decode the uploaded text document.")


def _extract_pdf_text(raw_bytes: bytes) -> str:
    if PdfReader is None:
        raise ValueError("PDF support is not installed on the backend.")

    reader = PdfReader(io.BytesIO(raw_bytes))
    pages = []
    for index, page in enumerate(reader.pages, start=1):
        text = (page.extract_text() or "").strip()
        if text:
            pages.append(f"[Page {index}]\n{text}")

    if not pages:
        raise ValueError("The uploaded PDF did not contain extractable text.")

    return "\n\n".join(pages)


def _extract_docx_text(raw_bytes: bytes) -> str:
    if Document is not None:
        document = Document(io.BytesIO(raw_bytes))
        paragraphs = [paragraph.text.strip() for paragraph in document.paragraphs if paragraph.text.strip()]

        if paragraphs:
            return "\n".join(paragraphs)

    # Fallback parser for environments where python-docx is missing.
    try:
        namespace = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as archive:
            xml_payload = archive.read("word/document.xml")
        root = ET.fromstring(xml_payload)
        paragraphs = []
        for paragraph in root.findall(".//w:p", namespace):
            texts = [node.text for node in paragraph.findall(".//w:t", namespace) if node.text]
            if texts:
                paragraphs.append("".join(texts).strip())
    except Exception as exc:
        raise ValueError(f"DOCX support is not installed on the backend and fallback parsing failed: {exc}") from exc

    if not paragraphs:
        raise ValueError("The uploaded DOCX did not contain extractable text.")

    return "\n".join(paragraphs)


def _extract_text_from_bytes(filename: str, raw_bytes: bytes) -> Tuple[str, str]:
    _, extension = os.path.splitext((filename or "").lower())
    if extension not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file type '{extension or 'unknown'}'. "
            "Supported formats: txt, md, rst, csv, json, yaml, yml, pdf, docx."
        )

    if len(raw_bytes) > MAX_DOCUMENT_BYTES:
        raise ValueError(f"File '{filename}' exceeds the 8 MB upload limit.")

    if extension in TEXT_EXTENSIONS:
        return _read_text_bytes(raw_bytes).strip(), extension
    if extension == ".pdf":
        return _extract_pdf_text(raw_bytes).strip(), extension
    if extension == ".docx":
        return _extract_docx_text(raw_bytes).strip(), extension

    raise ValueError(f"Unsupported file type '{extension}'.")


async def extract_documents(files: List[UploadFile]) -> Tuple[str, List[Dict[str, str]]]:
    if not files:
        raise ValueError("At least one design document must be uploaded.")

    extracted_sections: List[str] = []
    metadata: List[Dict[str, str]] = []

    for file in files:
        filename = file.filename or "uploaded-document"
        raw_bytes = await file.read()
        extracted_text, extension = _extract_text_from_bytes(filename, raw_bytes)
        if not extracted_text:
            raise ValueError(f"File '{filename}' did not contain usable text.")

        lowered = extracted_text.lower()
        role = "source_design"
        if (
            "threat modeling report" in lowered
            or "security score" in lowered and "confirmed risks" in lowered
            or "top 3 things to fix first" in lowered
        ):
            role = "reference_report"

        extracted_sections.append(
            f"Document: {filename}\n"
            f"Type: {extension.lstrip('.')}\n"
            f"Role: {role}\n"
            f"Content:\n{extracted_text}"
        )
        metadata.append(
            {
                "filename": filename,
                "type": extension.lstrip("."),
                "role": role,
                "characters": str(len(extracted_text)),
            }
        )

    return "\n\n---\n\n".join(extracted_sections), metadata
