# ruff: noqa: E501

from __future__ import annotations

import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

import pymupdf


def write_pdf(
    path: Path,
    text: str,
    *,
    hidden_text: str | None = None,
    covered_text: str | None = None,
) -> Path:
    document = pymupdf.open()
    page = document.new_page()
    page.insert_text((72, 72), text, fontsize=11)
    if hidden_text:
        page.insert_text((72, 100), hidden_text, fontsize=1, render_mode=3)
    if covered_text:
        page.insert_text((72, 125), covered_text, fontsize=11)
        page.draw_rect(
            pymupdf.Rect(65, 108, 400, 135),
            color=(1, 1, 1),
            fill=(1, 1, 1),
            fill_opacity=1,
        )
    document.save(path)
    document.close()
    return path


def write_docx(
    path: Path,
    text: str,
    *,
    hidden_text: str | None = None,
    styled_hidden_text: str | None = None,
    default_style_hidden_text: str | None = None,
    active_content: bool = False,
) -> Path:
    hidden_run = ""
    if hidden_text:
        hidden_run = (
            '<w:r><w:rPr><w:vanish/><w:color w:val="FFFFFF"/>'
            '<w:sz w:val="2"/></w:rPr>'
            f"<w:t>{escape(hidden_text)}</w:t></w:r>"
        )
    styled_hidden_run = ""
    if styled_hidden_text:
        styled_hidden_run = (
            '<w:r><w:rPr><w:rStyle w:val="HiddenDerived"/></w:rPr>'
            f"<w:t>{escape(styled_hidden_text)}</w:t></w:r>"
        )
    visible_paragraph_properties = (
        '<w:pPr><w:pStyle w:val="VisibleParagraph"/></w:pPr>' if default_style_hidden_text else ""
    )
    default_hidden_paragraph = (
        '<w:p w14:paraId="00000003"><w:r>'
        f"<w:t>{escape(default_style_hidden_text)}</w:t></w:r></w:p>"
        if default_style_hidden_text
        else ""
    )
    document_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
 xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml">
  <w:body>
    <w:p w14:paraId="00000001">{visible_paragraph_properties}<w:r><w:t>{escape(text)}</w:t></w:r>{hidden_run}{styled_hidden_run}</w:p>
    {default_hidden_paragraph}
    <w:tbl><w:tr><w:tc><w:p w14:paraId="00000002"><w:r><w:t>표 셀</w:t></w:r></w:p></w:tc></w:tr></w:tbl>
    <w:sectPr/>
  </w:body>
</w:document>"""
    content_types = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""
    relationships = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""
    default_styles = (
        """<w:style w:type="paragraph" w:styleId="HiddenDefault" w:default="1">
    <w:rPr><w:vanish/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="VisibleParagraph"/>"""
        if default_style_hidden_text
        else ""
    )
    styles_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="character" w:styleId="HiddenBase">
    <w:rPr><w:vanish/><w:color w:val="FFFFFF"/></w:rPr>
  </w:style>
  <w:style w:type="character" w:styleId="HiddenDerived">
    <w:basedOn w:val="HiddenBase"/>
  </w:style>
  {default_styles}
</w:styles>"""

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
        package.writestr("[Content_Types].xml", content_types)
        package.writestr("_rels/.rels", relationships)
        package.writestr("word/document.xml", document_xml)
        if styled_hidden_text or default_style_hidden_text:
            package.writestr("word/styles.xml", styles_xml)
        if active_content:
            package.writestr("word/vbaProject.bin", b"not executable test payload")
    return path


def write_hwpx(
    path: Path,
    text: str,
    *,
    hidden_text: str | None = None,
    active_content: bool = False,
) -> Path:
    hidden_run = ""
    if hidden_text:
        hidden_run = f'<hp:run charPrIDRef="1"><hp:t>{escape(hidden_text)}</hp:t></hp:run>'
    content_hpf = """<?xml version="1.0" encoding="UTF-8"?>
<opf:package xmlns:opf="http://www.idpf.org/2007/opf/"
 xmlns:dc="http://purl.org/dc/elements/1.1/">
  <opf:metadata><dc:title>정책 문서</dc:title><dc:creator>IndexGuard</dc:creator></opf:metadata>
  <opf:manifest>
    <opf:item id="header" href="header.xml" media-type="application/xml"/>
    <opf:item id="section0" href="section0.xml" media-type="application/xml"/>
  </opf:manifest>
  <opf:spine><opf:itemref idref="section0"/></opf:spine>
</opf:package>"""
    header_xml = """<?xml version="1.0" encoding="UTF-8"?>
<hh:head xmlns:hh="http://www.hancom.co.kr/hwpml/2011/head" secCnt="1">
  <hh:refList><hh:charProperties itemCnt="2">
    <hh:charPr id="0" height="1100" textColor="#000000"/>
    <hh:charPr id="1" height="100" textColor="#FFFFFF"/>
  </hh:charProperties></hh:refList>
</hh:head>"""
    section_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<hs:sec xmlns:hs="http://www.hancom.co.kr/hwpml/2011/section"
 xmlns:hp="http://www.hancom.co.kr/hwpml/2011/paragraph">
  <hp:p id="p1"><hp:run charPrIDRef="0"><hp:t>{escape(text)}</hp:t></hp:run>{hidden_run}</hp:p>
  <hp:tbl><hp:tr><hp:tc><hp:p id="p2"><hp:run charPrIDRef="0"><hp:t>표 셀</hp:t></hp:run></hp:p></hp:tc></hp:tr></hp:tbl>
</hs:sec>"""

    with zipfile.ZipFile(path, "w") as package:
        package.writestr(
            zipfile.ZipInfo("mimetype"),
            b"application/hwp+zip",
            compress_type=zipfile.ZIP_STORED,
        )
        package.writestr("Contents/content.hpf", content_hpf, compress_type=zipfile.ZIP_DEFLATED)
        package.writestr("Contents/header.xml", header_xml, compress_type=zipfile.ZIP_DEFLATED)
        package.writestr("Contents/section0.xml", section_xml, compress_type=zipfile.ZIP_DEFLATED)
        if active_content:
            package.writestr(
                "Scripts/sourceScripts",
                b"function attack() { return true; }",
                compress_type=zipfile.ZIP_DEFLATED,
            )
    return path
