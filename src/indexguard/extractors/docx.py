"""Safe OOXML/DOCX extraction with inherited hidden-style evidence."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
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

CFB_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
WORD_NAMESPACES = {
    "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "http://purl.oclc.org/ooxml/wordprocessingml/main",
}


def _children(element: ET.Element, local: str) -> list[ET.Element]:
    return [child for child in element if split_xml_name(child.tag)[1] == local]


def _descendants(element: ET.Element, local: str) -> list[ET.Element]:
    return [child for child in element.iter() if split_xml_name(child.tag)[1] == local]


def _package_descriptor(package: SafeZipPackage) -> tuple[str, str]:
    if not package.has_member("[Content_Types].xml") or not package.has_member("_rels/.rels"):
        raise FormatMismatchError("ZIP package is not an OOXML Word document")
    content_types = package.parse_xml("[Content_Types].xml")
    overrides: dict[str, str] = {}
    for override in _descendants(content_types, "Override"):
        part_name = attr_by_local_name(override.attrib, "PartName")
        content_type = attr_by_local_name(override.attrib, "ContentType")
        if part_name and content_type:
            overrides[part_name.lstrip("/")] = content_type

    relationships = package.parse_xml("_rels/.rels")
    main_parts: list[str] = []
    for relationship in _descendants(relationships, "Relationship"):
        rel_type = attr_by_local_name(relationship.attrib, "Type") or ""
        target_mode = (attr_by_local_name(relationship.attrib, "TargetMode") or "Internal").lower()
        target = attr_by_local_name(relationship.attrib, "Target")
        if rel_type.endswith("/officeDocument") and target and target_mode != "external":
            main_parts.append(package.resolve_target(None, target))
    if len(main_parts) != 1 or not package.has_member(main_parts[0]):
        raise FormatMismatchError("OOXML package has no unique Word main document part")
    main_part = main_parts[0]
    content_type = overrides.get(main_part, "")
    if "wordprocessingml" not in content_type and "ms-word" not in content_type:
        raise FormatMismatchError("OOXML main part is not a WordprocessingML document")
    return main_part, content_type


def _on_off(element: ET.Element | None) -> bool | None:
    if element is None:
        return None
    value = attr_by_local_name(element.attrib, "val")
    return True if value is None else value.strip().lower() not in {"0", "false", "off", "no"}


@dataclass(frozen=True, slots=True)
class _StyleDefinition:
    based_on: str | None
    properties: dict[str, object]


@dataclass(frozen=True, slots=True)
class _StyleCatalog:
    defaults: dict[str, object]
    definitions: dict[str, _StyleDefinition]
    default_paragraph_style: str | None = None
    default_character_style: str | None = None


def _run_properties(run_properties: ET.Element | None) -> dict[str, object]:
    if run_properties is None:
        return {}
    properties = {split_xml_name(child.tag)[1]: child for child in run_properties}
    result: dict[str, object] = {}
    for name in ("vanish", "webHidden"):
        if (node := properties.get(name)) is not None:
            result[name] = bool(_on_off(node))
    color_node = properties.get("color")
    if color_node is not None:
        result["color"] = normalize_color_hex(attr_by_local_name(color_node.attrib, "val"))
    size_node = properties.get("sz")
    if size_node is None:
        size_node = properties.get("szCs")
    if size_node is not None:
        try:
            result["size"] = float(attr_by_local_name(size_node.attrib, "val") or "") / 2.0
        except ValueError:
            result["size"] = None
    highlight_node = properties.get("highlight")
    if highlight_node is not None:
        result["highlight"] = (attr_by_local_name(highlight_node.attrib, "val") or "").lower()
    style_ref_node = properties.get("rStyle")
    if style_ref_node is not None:
        result["style_ref"] = attr_by_local_name(style_ref_node.attrib, "val")
    return result


def _load_style_catalog(package: SafeZipPackage) -> _StyleCatalog:
    style_part = next((name for name in package.names if name.lower() == "word/styles.xml"), None)
    if style_part is None:
        return _StyleCatalog(defaults={}, definitions={})

    root = package.parse_xml(style_part)
    default_properties: dict[str, object] = {}
    run_default = next(iter(_descendants(root, "rPrDefault")), None)
    if run_default is not None:
        default_properties = _run_properties(next(iter(_children(run_default, "rPr")), None))

    definitions: dict[str, _StyleDefinition] = {}
    default_paragraph_style: str | None = None
    default_character_style: str | None = None
    for style in _children(root, "style"):
        style_id = attr_by_local_name(style.attrib, "styleId")
        if not style_id:
            continue
        if style_id in definitions:
            raise MalformedDocumentError("DOCX contains duplicate style identifiers")
        based_on_node = next(iter(_children(style, "basedOn")), None)
        based_on = (
            attr_by_local_name(based_on_node.attrib, "val") if based_on_node is not None else None
        )
        definitions[style_id] = _StyleDefinition(
            based_on=based_on,
            properties=_run_properties(next(iter(_children(style, "rPr")), None)),
        )
        is_default = (attr_by_local_name(style.attrib, "default") or "").lower() in {
            "1",
            "true",
            "on",
        }
        style_type = (attr_by_local_name(style.attrib, "type") or "").lower()
        if is_default and style_type == "paragraph":
            if default_paragraph_style is not None:
                raise MalformedDocumentError("DOCX declares multiple default paragraph styles")
            default_paragraph_style = style_id
        if is_default and style_type == "character":
            if default_character_style is not None:
                raise MalformedDocumentError("DOCX declares multiple default character styles")
            default_character_style = style_id
    return _StyleCatalog(
        defaults=default_properties,
        definitions=definitions,
        default_paragraph_style=default_paragraph_style,
        default_character_style=default_character_style,
    )


def _resolved_style_properties(
    style_id: str | None,
    catalog: _StyleCatalog,
    visiting: frozenset[str] = frozenset(),
) -> dict[str, object]:
    if not style_id:
        return {}
    if style_id in visiting:
        raise MalformedDocumentError("DOCX style inheritance contains a cycle")
    definition = catalog.definitions.get(style_id)
    if definition is None:
        return {}
    resolved = _resolved_style_properties(
        definition.based_on,
        catalog,
        visiting | {style_id},
    )
    resolved.update(definition.properties)
    return resolved


def _paragraph_style_ref(paragraph: ET.Element) -> str | None:
    paragraph_properties = next(iter(_children(paragraph, "pPr")), None)
    if paragraph_properties is None:
        return None
    style_node = next(iter(_children(paragraph_properties, "pStyle")), None)
    return attr_by_local_name(style_node.attrib, "val") if style_node is not None else None


def _effective_style(
    run: ET.Element,
    paragraph: ET.Element,
    catalog: _StyleCatalog,
) -> TextStyle:
    direct = _run_properties(next(iter(_children(run, "rPr")), None))
    paragraph_style = _paragraph_style_ref(paragraph) or catalog.default_paragraph_style
    run_style_value = direct.get("style_ref")
    run_style = (
        run_style_value if isinstance(run_style_value, str) else catalog.default_character_style
    )

    properties = dict(catalog.defaults)
    properties.update(_resolved_style_properties(paragraph_style, catalog))
    properties.update(_resolved_style_properties(run_style, catalog))
    properties.update(direct)

    color_value = properties.get("color")
    color = color_value if isinstance(color_value, str) else None
    size_value = properties.get("size")
    size = float(size_value) if isinstance(size_value, (int, float)) else None
    highlight_value = properties.get("highlight")
    highlight = highlight_value if isinstance(highlight_value, str) else None
    white_on_visible_background = highlight not in {None, "none", "white"}
    hidden = properties.get("vanish") is True or properties.get("webHidden") is True
    hidden = hidden or (is_near_white_hex(color) and not white_on_visible_background)
    hidden = hidden or (size is not None and size <= 1.0)
    return TextStyle(
        color_hex=color,
        font_size_pt=size,
        hidden=hidden,
        style_ref=run_style or paragraph_style,
    )


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


def _has_ancestor(
    element: ET.Element,
    parents: dict[ET.Element, ET.Element],
    names: set[str],
) -> bool:
    current = parents.get(element)
    while current is not None:
        if split_xml_name(current.tag)[1] in names:
            return True
        current = parents.get(current)
    return False


class DocxExtractor(BaseExtractor):
    format = DocumentFormat.DOCX
    parser_name = "ooxml-style-security"

    @classmethod
    def probe(cls, staged: StagedFile, limits: ExtractionLimits = DEFAULT_LIMITS) -> None:
        verify_staged_file(staged, limits)
        prefix = read_prefix(staged.path, 8)
        if prefix == CFB_MAGIC:
            raise EncryptedDocumentError("encrypted or legacy Compound File Word document")
        if prefix[:4] != ZIP_LOCAL_FILE_MAGIC:
            raise FormatMismatchError("DOCX extension does not match an OOXML ZIP package")
        with SafeZipPackage(staged, limits) as package:
            _package_descriptor(package)

    def _extract_part(
        self,
        package: SafeZipPackage,
        part: str,
        scope: SourceScope,
        collector: ExtractionCollector,
        styles: _StyleCatalog,
    ) -> int:
        root = package.parse_xml(part)
        parents = {child: parent for parent in root.iter() for child in parent}
        paragraphs = [node for node in root.iter() if split_xml_name(node.tag)[1] == "p"]
        paragraph_index = {id(node): index for index, node in enumerate(paragraphs)}
        groups: OrderedDict[tuple[int, SourceScope], tuple[ET.Element, ET.Element, list[str]]] = (
            OrderedDict()
        )
        revision_found = False
        for node in root.iter():
            namespace, local = split_xml_name(node.tag)
            if namespace not in WORD_NAMESPACES or local not in {
                "t",
                "delText",
                "instrText",
                "tab",
                "br",
                "cr",
            }:
                continue
            run = _nearest(node, parents, "r")
            paragraph = _nearest(node, parents, "p")
            if run is None or paragraph is None:
                continue
            deleted = local in {"delText", "instrText"} or _has_ancestor(
                node, parents, {"del", "moveFrom"}
            )
            unit_scope = (
                SourceScope.AUXILIARY if deleted or scope is SourceScope.AUXILIARY else scope
            )
            revision_found = (
                revision_found or deleted or _has_ancestor(node, parents, {"ins", "moveTo"})
            )
            token = "\t" if local == "tab" else "\n" if local in {"br", "cr"} else (node.text or "")
            key = (id(run), unit_scope)
            if key not in groups:
                groups[key] = (run, paragraph, [])
            groups[key][2].append(token)

        run_counters: dict[int, int] = {}
        for group_index, (_key, (run, paragraph, tokens)) in enumerate(groups.items()):
            text = "".join(tokens)
            if not text.strip():
                continue
            p_index = paragraph_index.get(id(paragraph), 0)
            run_index = run_counters.get(id(paragraph), 0)
            run_counters[id(paragraph)] = run_index + 1
            paragraph_id = attr_by_local_name(paragraph.attrib, "paraId") or str(p_index)
            style = _effective_style(run, paragraph, styles)
            hidden = bool(style.hidden)
            collector.add_unit(
                TextUnit(
                    id=f"{part}:p{p_index}:r{run_index}:{group_index}",
                    text=text,
                    location=TextLocation(
                        part=part,
                        paragraph_id=paragraph_id,
                        run_index=run_index,
                    ),
                    style=style,
                    visibility=Visibility.HIDDEN_SUSPECTED if hidden else Visibility.VISIBLE,
                    source_scope=_key[1],
                )
            )
        if revision_found:
            collector.add_artifact(
                Artifact(
                    type="TRACKED_CHANGES",
                    reason="Word revision markup is present.",
                    path=part,
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
            main_part, content_type = _package_descriptor(package)
            styles = _load_style_catalog(package)
            lower_names = {name.lower(): name for name in package.names}
            active_prefixes = ("word/activex/", "word/embeddings/")
            for lower_name, original in lower_names.items():
                if lower_name.endswith("vbaproject.bin") or lower_name.startswith(active_prefixes):
                    collector.add_artifact(
                        Artifact(
                            type="ACTIVE_CONTENT",
                            reason="DOCX contains macro, ActiveX, or embedded-object content.",
                            path=original,
                        )
                    )
            if "macroenabled" in content_type.lower():
                collector.add_artifact(
                    Artifact(type="ACTIVE_CONTENT", reason="Word package is macro-enabled.")
                )

            for rels_part in (name for name in package.names if name.endswith(".rels")):
                rels = package.parse_xml(rels_part)
                for relationship in _descendants(rels, "Relationship"):
                    rel_type = (attr_by_local_name(relationship.attrib, "Type") or "").lower()
                    mode = (attr_by_local_name(relationship.attrib, "TargetMode") or "").lower()
                    target = attr_by_local_name(relationship.attrib, "Target")
                    if mode == "external" and target:
                        artifact_type = (
                            "EXTERNAL_REFERENCE"
                            if rel_type.endswith("/hyperlink")
                            else "ACTIVE_CONTENT"
                        )
                        collector.add_artifact(
                            Artifact(
                                type=artifact_type,
                                reason="DOCX contains an external package relationship.",
                                path=target,
                                metadata={"relationship_type": rel_type},
                            )
                        )
                    elif any(
                        marker in rel_type for marker in ("oleobject", "/control", "/package")
                    ):
                        collector.add_artifact(
                            Artifact(
                                type="ACTIVE_CONTENT",
                                reason="DOCX relationship references active or embedded content.",
                                path=target,
                            )
                        )

            paragraph_count = self._extract_part(
                package,
                main_part,
                SourceScope.BODY,
                collector,
                styles,
            )
            auxiliary_parts = [
                name
                for name in package.names
                if name.startswith("word/")
                and name.endswith(".xml")
                and any(
                    marker in name.rsplit("/", 1)[-1]
                    for marker in ("header", "footer", "footnotes", "endnotes", "comments")
                )
            ]
            for part in auxiliary_parts:
                self._extract_part(package, part, SourceScope.AUXILIARY, collector, styles)

        return build_snapshot(
            staged=staged,
            document_id=document_id,
            document_format=self.format,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            collector=collector,
            metadata={
                "main_part": main_part,
                "content_type": content_type,
                "paragraph_count": paragraph_count,
                "auxiliary_parts": auxiliary_parts,
                "style_count": len(styles.definitions),
            },
        )


def extract_docx(
    staged: StagedFile,
    document_id: str,
    limits: ExtractionLimits = DEFAULT_LIMITS,
) -> DocumentSnapshot:
    return DocxExtractor().extract(staged, document_id, limits)
