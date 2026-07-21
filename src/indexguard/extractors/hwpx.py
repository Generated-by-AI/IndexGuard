"""Safe HWPX ZIP/XML extraction in OPF spine order."""

from __future__ import annotations

from collections import OrderedDict
from xml.etree import ElementTree as ET

from indexguard.contracts import (
    Artifact,
    DocumentFormat,
    DocumentSnapshot,
    SourceScope,
    TextLocation,
    TextStyle,
    TextUnit,
    Visibility,
)
from indexguard.errors import EncryptedDocumentError, FormatMismatchError, MalformedDocumentError
from indexguard.storage import StagedFile

from .base import (
    DEFAULT_LIMITS,
    BaseExtractor,
    ExtractionCollector,
    ExtractionLimits,
    attr_by_local_name,
    build_snapshot,
    is_near_white_hex,
    normalize_color_hex,
    read_prefix,
    split_xml_name,
    verify_staged_file,
)
from .safe_zip import ZIP_LOCAL_FILE_MAGIC, SafeZipPackage

HWPX_MIMETYPE = b"application/hwp+zip"
PARAGRAPH_NAMESPACE_PREFIX = "http://www.hancom.co.kr/hwpml/"


def _descendants(element: ET.Element, local: str) -> list[ET.Element]:
    return [child for child in element.iter() if split_xml_name(child.tag)[1] == local]


def _nearest(
    element: ET.Element,
    parents: dict[ET.Element, ET.Element],
    local_name: str,
) -> ET.Element | None:
    current = parents.get(element)
    while current is not None:
        if split_xml_name(current.tag)[1] == local_name:
            return current
        current = parents.get(current)
    return None


def _descriptor(package: SafeZipPackage) -> tuple[list[str], dict[str, tuple[str, str]]]:
    required = ("mimetype", "Contents/content.hpf", "Contents/header.xml")
    if not all(package.has_member(name) for name in required):
        raise FormatMismatchError("ZIP package is missing required HWPX members")
    if package.read_member("mimetype", max_bytes=128).strip() != HWPX_MIMETYPE:
        raise FormatMismatchError("HWPX mimetype signature is invalid")

    content = package.parse_xml("Contents/content.hpf")
    manifest: dict[str, tuple[str, str]] = {}
    for item in _descendants(content, "item"):
        item_id = attr_by_local_name(item.attrib, "id")
        href = attr_by_local_name(item.attrib, "href")
        media_type = attr_by_local_name(item.attrib, "media-type") or ""
        if item_id and href:
            # HWPX producers disagree on whether manifest href values are
            # relative to content.hpf or rooted at the package. Prefer the
            # standard relative location, then accept a verified root-relative
            # member. Both paths go through SafeZipPackage resolution.
            target = package.resolve_target("Contents/content.hpf", href)
            if not package.has_member(target):
                root_target = package.resolve_target(None, href)
                if package.has_member(root_target):
                    target = root_target
            if not package.has_member(target):
                raise MalformedDocumentError(f"HWPX manifest target is missing: {target}")
            manifest[item_id] = (target, media_type)
    sections: list[str] = []
    for itemref in _descendants(content, "itemref"):
        item_id = attr_by_local_name(itemref.attrib, "idref")
        if not item_id or item_id not in manifest:
            raise MalformedDocumentError("HWPX spine contains an unresolved itemref")
        sections.append(manifest[item_id][0])
    if not sections:
        raise MalformedDocumentError("HWPX spine contains no document sections")
    return sections, manifest


def _character_styles(header: ET.Element) -> dict[str, TextStyle]:
    styles: dict[str, TextStyle] = {}
    for char_pr in _descendants(header, "charPr"):
        style_id = attr_by_local_name(char_pr.attrib, "id")
        if style_id is None:
            continue
        color = normalize_color_hex(attr_by_local_name(char_pr.attrib, "textColor"))
        size: float | None = None
        try:
            raw_height = attr_by_local_name(char_pr.attrib, "height")
            size = float(raw_height) / 100.0 if raw_height is not None else None
        except ValueError:
            size = None
        explicit_hidden = any(
            (attr_by_local_name(char_pr.attrib, key) or "").lower() in {"1", "true", "on"}
            for key in ("hidden", "invisible")
        )
        hidden = explicit_hidden or is_near_white_hex(color) or (size is not None and size <= 1.0)
        styles[style_id] = TextStyle(
            color_hex=color,
            font_size_pt=size,
            hidden=hidden,
            style_ref=style_id,
        )
    return styles


class HwpxExtractor(BaseExtractor):
    format = DocumentFormat.HWPX
    # HWPX is an XML/ZIP document format.  Parse its OWPML spine directly so
    # extraction is deterministic and does not depend on a desktop renderer.
    parser_name = "owpml-spine-security"

    @classmethod
    def probe(cls, staged: StagedFile, limits: ExtractionLimits = DEFAULT_LIMITS) -> None:
        verify_staged_file(staged, limits)
        if read_prefix(staged.path, 4) != ZIP_LOCAL_FILE_MAGIC:
            raise FormatMismatchError("HWPX extension does not match a ZIP package")
        with SafeZipPackage(staged, limits) as package:
            _descriptor(package)

    def _extract_section(
        self,
        package: SafeZipPackage,
        part: str,
        section_index: int,
        styles: dict[str, TextStyle],
        collector: ExtractionCollector,
    ) -> int:
        root = package.parse_xml(part)
        parents = {child: parent for parent in root.iter() for child in parent}
        paragraphs = [node for node in root.iter() if split_xml_name(node.tag)[1] == "p"]
        paragraph_index = {id(node): index for index, node in enumerate(paragraphs)}
        groups: OrderedDict[int, tuple[ET.Element, ET.Element, list[str]]] = OrderedDict()
        for node in root.iter():
            namespace, local = split_xml_name(node.tag)
            if not namespace or not namespace.startswith(PARAGRAPH_NAMESPACE_PREFIX):
                continue
            if local not in {"t", "lineBreak", "tab"}:
                continue
            run = _nearest(node, parents, "run")
            paragraph = _nearest(node, parents, "p")
            if run is None or paragraph is None:
                continue
            if local == "t":
                token = node.text or ""
            elif local == "lineBreak":
                token = "\n" + (node.tail or "")
            else:
                token = "\t" + (node.tail or "")
            key = id(run)
            if key not in groups:
                groups[key] = (run, paragraph, [])
            groups[key][2].append(token)

        run_counters: dict[int, int] = {}
        for group_index, (run, paragraph, tokens) in enumerate(groups.values()):
            text = "".join(tokens)
            if not text.strip():
                continue
            p_index = paragraph_index.get(id(paragraph), 0)
            run_index = run_counters.get(id(paragraph), 0)
            run_counters[id(paragraph)] = run_index + 1
            paragraph_id = attr_by_local_name(paragraph.attrib, "id") or str(p_index)
            style_ref = attr_by_local_name(run.attrib, "charPrIDRef")
            style = styles.get(style_ref or "", TextStyle(style_ref=style_ref))
            hidden = bool(style.hidden)
            collector.add_unit(
                TextUnit(
                    id=f"section{section_index}:p{paragraph_id}:r{run_index}:{group_index}",
                    text=text,
                    location=TextLocation(
                        section=section_index,
                        paragraph_id=paragraph_id,
                        run_index=run_index,
                        part=part,
                    ),
                    style=style.model_copy(deep=True),
                    visibility=Visibility.HIDDEN_SUSPECTED if hidden else Visibility.VISIBLE,
                    source_scope=SourceScope.BODY,
                )
            )
        return len(paragraphs)

    def extract(
        self,
        staged: StagedFile,
        document_id: str,
        limits: ExtractionLimits = DEFAULT_LIMITS,
    ) -> DocumentSnapshot:
        self.probe(staged, limits)
        collector = ExtractionCollector(limits)
        with SafeZipPackage(staged, limits) as package:
            sections, manifest = _descriptor(package)
            for name in package.names:
                lower_name = name.lower()
                if lower_name.startswith("meta-inf/") and lower_name.endswith(".xml"):
                    root = package.parse_xml(name)
                    if any(
                        "encrypt" in split_xml_name(node.tag)[1].lower() for node in root.iter()
                    ):
                        raise EncryptedDocumentError("encrypted HWPX cannot be inspected")
                if lower_name.startswith("scripts/") and package.info(name).file_size:
                    collector.add_artifact(
                        Artifact(
                            type="ACTIVE_CONTENT",
                            reason="HWPX contains a non-empty script payload.",
                            path=name,
                        )
                    )
                if lower_name.startswith("bindata/") and not lower_name.endswith(
                    (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp")
                ):
                    collector.add_artifact(
                        Artifact(
                            type="ACTIVE_CONTENT",
                            reason="HWPX contains OLE or an unscannable binary object.",
                            path=name,
                        )
                    )

            styles = _character_styles(package.parse_xml("Contents/header.xml"))
            paragraph_count = 0
            for section_index, section in enumerate(sections):
                paragraph_count += self._extract_section(
                    package, section, section_index, styles, collector
                )

            auxiliary_parts: list[str] = []
            excluded = set(sections) | {"Contents/header.xml", "Contents/content.hpf"}
            for part, _media_type in manifest.values():
                if (
                    part in excluded
                    or not part.lower().endswith(".xml")
                    or part.startswith("Scripts/")
                ):
                    continue
                root = package.parse_xml(part)
                texts = [
                    node.text or ""
                    for node in root.iter()
                    if split_xml_name(node.tag)[1] in {"t", "title", "description"}
                    and (node.text or "").strip()
                ]
                if texts:
                    auxiliary_parts.append(part)
                    collector.add_unit(
                        TextUnit(
                            id=f"aux:{part}",
                            text="\n".join(texts),
                            location=TextLocation(part=part),
                            source_scope=SourceScope.AUXILIARY,
                        )
                    )

        return build_snapshot(
            staged=staged,
            document_id=document_id,
            document_format=self.format,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            collector=collector,
            metadata={
                "sections": sections,
                "paragraph_count": paragraph_count,
                "char_style_count": len(styles),
                "auxiliary_parts": auxiliary_parts,
                "loader": {
                    "name": "owpml-spine",
                    "status": "used",
                    "detail": "direct_hwpx_xml_extraction",
                },
            },
        )


def extract_hwpx(
    staged: StagedFile,
    document_id: str,
    limits: ExtractionLimits = DEFAULT_LIMITS,
) -> DocumentSnapshot:
    return HwpxExtractor().extract(staged, document_id, limits)
