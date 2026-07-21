"""Bounded plain-text extraction for Markdown source documents."""

from __future__ import annotations

from indexguard.contracts import DocumentFormat, SourceScope, TextLocation, TextStyle, TextUnit
from indexguard.errors import MalformedDocumentError
from indexguard.storage import StagedFile

from .base import (
    DEFAULT_LIMITS,
    BaseExtractor,
    ExtractionCollector,
    ExtractionLimits,
    build_snapshot,
    read_staged_bytes,
)


class MarkdownExtractor(BaseExtractor):
    format = DocumentFormat.MARKDOWN
    parser_name = "markdown-utf8"
    parser_version = "1.0.0"

    @classmethod
    def probe(cls, staged: StagedFile, limits: ExtractionLimits = DEFAULT_LIMITS) -> None:
        data = read_staged_bytes(staged, limits)
        try:
            data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise MalformedDocumentError("Markdown must be UTF-8 encoded") from exc

    def extract(
        self,
        staged: StagedFile,
        document_id: str,
        limits: ExtractionLimits = DEFAULT_LIMITS,
    ):
        text = read_staged_bytes(staged, limits).decode("utf-8-sig")
        collector = ExtractionCollector(limits)
        for number, line in enumerate(text.splitlines(), start=1):
            if line.strip():
                collector.add_unit(
                    TextUnit(
                        id=f"line-{number}",
                        text=line,
                        location=TextLocation(paragraph_id=str(number)),
                        style=TextStyle(),
                        source_scope=SourceScope.BODY,
                    )
                )
        return build_snapshot(
            staged=staged,
            document_id=document_id,
            document_format=self.format,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            collector=collector,
            metadata={"source_encoding": "utf-8"},
            visible_body_override=text,
        )
