from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class DoclingExtractionUnavailable(RuntimeError):
    pass


def docling_available() -> bool:
    try:
        from docling.document_converter import DocumentConverter  # noqa: F401
    except ModuleNotFoundError:
        return False
    return True


def extract_with_docling(
    path: Path | str,
    *,
    allow_ocr: bool = False,
    docling_json_path: Path | str | None = None,
    markdown_path: Path | str | None = None,
) -> dict[str, Any]:
    try:
        converter = _converter(allow_ocr=allow_ocr)
    except ModuleNotFoundError as exc:
        raise DoclingExtractionUnavailable("Docling is not installed; no fallback extractor is enabled") from exc
    result = converter.convert(str(path))
    document = result.document
    markdown = str(document.export_to_markdown())
    units, warnings = _page_units(document, markdown)
    json_body = ""
    if hasattr(document, "export_to_dict"):
        json_body = json.dumps(document.export_to_dict(), indent=2, sort_keys=True)
    if docling_json_path is not None:
        target = Path(docling_json_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if hasattr(document, "save_as_json"):
            document.save_as_json(target)
        else:
            target.write_text(json_body + "\n", encoding="utf-8")
    if markdown_path is not None:
        target = Path(markdown_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if hasattr(document, "save_as_markdown"):
            document.save_as_markdown(target)
        else:
            target.write_text(markdown + "\n", encoding="utf-8")
    return {
        "backend": "docling",
        "text": markdown,
        "docling_json": json_body,
        "docling_json_path": str(docling_json_path) if docling_json_path is not None else "",
        "markdown_path": str(markdown_path) if markdown_path is not None else "",
        "units": units,
        "warnings": warnings,
    }


def _converter(*, allow_ocr: bool) -> Any:
    from docling.document_converter import DocumentConverter

    try:
        from docling.datamodel.base_models import InputFormat
        from docling.datamodel.pipeline_options import PdfPipelineOptions
        from docling.document_converter import ImageFormatOption, PdfFormatOption
    except Exception:
        return DocumentConverter()
    pdf_options = PdfPipelineOptions()
    if hasattr(pdf_options, "do_ocr"):
        pdf_options.do_ocr = bool(allow_ocr)
    if hasattr(pdf_options, "enable_remote_services"):
        pdf_options.enable_remote_services = False
    image_options = PdfPipelineOptions()
    if hasattr(image_options, "do_ocr"):
        image_options.do_ocr = bool(allow_ocr)
    if hasattr(image_options, "enable_remote_services"):
        image_options.enable_remote_services = False
    return DocumentConverter(
        format_options={
            InputFormat.PDF: PdfFormatOption(pipeline_options=pdf_options),
            InputFormat.IMAGE: ImageFormatOption(pipeline_options=image_options),
        }
    )


def _page_units(document: Any, full_markdown: str) -> tuple[list[dict[str, Any]], list[str]]:
    pages = getattr(document, "pages", None)
    warnings: list[str] = []
    if isinstance(pages, dict) and pages:
        units: list[dict[str, Any]] = []
        for index, page_no in enumerate(sorted(pages.keys())):
            try:
                page_text = str(document.export_to_markdown(page_no=page_no))
            except TypeError:
                return _document_unit(full_markdown), ["docling_page_export_unavailable"]
            page_text = page_text.strip()
            if not page_text:
                warnings.append(f"no_text_on_page:{page_no}")
            units.append(
                {
                    "location_type": "page",
                    "index": index,
                    "text": page_text,
                    "metadata": {"page": int(page_no) if isinstance(page_no, int) else page_no},
                }
            )
        return units, warnings
    return _document_unit(full_markdown), warnings


def _document_unit(text: str) -> list[dict[str, Any]]:
    return [{"location_type": "document", "index": 0, "text": text, "metadata": {}}]
