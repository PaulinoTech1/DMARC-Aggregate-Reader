"""Safe, dependency-free parsing for aggregate DMARC XML reports."""

from __future__ import annotations

import gzip
import io
import ipaddress
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator
import xml.etree.ElementTree as ET


SUPPORTED_SUFFIXES = {".xml", ".zip", ".gz"}
MAX_XML_BYTES = 50 * 1024 * 1024


def _text(node: ET.Element, path: str, default: str = "") -> str:
    found = node.find(path)
    return (found.text or "").strip() if found is not None else default


def _integer(node: ET.Element, path: str) -> int:
    try:
        return int(_text(node, path, "0"))
    except ValueError:
        return 0


def _timestamp(value: str) -> str:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, OSError, OverflowError):
        return value or "Unknown"


@dataclass(slots=True)
class DmarcRow:
    source_file: str
    organization: str
    report_id: str
    begin: str
    end: str
    domain: str
    source_ip: str
    count: int
    disposition: str
    dkim: str
    spf: str
    header_from: str
    envelope_from: str
    dkim_domains: str = ""
    spf_domains: str = ""

    @property
    def aligned(self) -> bool:
        return self.dkim.lower() == "pass" or self.spf.lower() == "pass"


@dataclass(slots=True)
class ParseIssue:
    source_file: str
    message: str


@dataclass
class ParseResult:
    rows: list[DmarcRow] = field(default_factory=list)
    issues: list[ParseIssue] = field(default_factory=list)
    files_seen: int = 0
    reports_parsed: int = 0


def discover_files(folder: Path, recursive: bool = True) -> list[Path]:
    iterator = folder.rglob("*") if recursive else folder.glob("*")
    return sorted(
        (path for path in iterator if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES),
        key=lambda path: str(path).lower(),
    )


def _xml_payloads(path: Path) -> Iterator[tuple[str, bytes]]:
    suffix = path.suffix.lower()
    if suffix == ".xml":
        data = path.read_bytes()
        if len(data) > MAX_XML_BYTES:
            raise ValueError("XML exceeds the 50 MB safety limit")
        yield path.name, data
    elif suffix == ".gz":
        with gzip.open(path, "rb") as stream:
            data = stream.read(MAX_XML_BYTES + 1)
        if len(data) > MAX_XML_BYTES:
            raise ValueError("Decompressed XML exceeds the 50 MB safety limit")
        yield path.name, data
    elif suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            members = [item for item in archive.infolist() if not item.is_dir() and item.filename.lower().endswith(".xml")]
            if not members:
                raise ValueError("ZIP contains no XML reports")
            for member in members:
                if member.file_size > MAX_XML_BYTES:
                    raise ValueError(f"{member.filename} exceeds the 50 MB safety limit")
                with archive.open(member) as stream:
                    data = stream.read(MAX_XML_BYTES + 1)
                if len(data) > MAX_XML_BYTES:
                    raise ValueError(f"{member.filename} exceeds the 50 MB safety limit")
                yield f"{path.name} / {member.filename}", data


def parse_xml(data: bytes, source_file: str) -> list[DmarcRow]:
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("DTD/entity declarations are not allowed")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML: {exc}") from exc

    metadata = root.find("report_metadata")
    policy = root.find("policy_published")
    if metadata is None or policy is None:
        raise ValueError("Not a DMARC aggregate report")

    organization = _text(metadata, "org_name", "Unknown")
    report_id = _text(metadata, "report_id", "Unknown")
    begin = _timestamp(_text(metadata, "date_range/begin"))
    end = _timestamp(_text(metadata, "date_range/end"))
    domain = _text(policy, "domain", "Unknown")
    rows: list[DmarcRow] = []
    for record in root.findall("record"):
        source_ip = _text(record, "row/source_ip", "Unknown")
        try:
            if source_ip != "Unknown":
                ipaddress.ip_address(source_ip)
        except ValueError:
            source_ip = f"{source_ip} (invalid)"
        dkim_results = record.findall("auth_results/dkim")
        spf_results = record.findall("auth_results/spf")
        rows.append(DmarcRow(
            source_file=source_file,
            organization=organization,
            report_id=report_id,
            begin=begin,
            end=end,
            domain=domain,
            source_ip=source_ip,
            count=_integer(record, "row/count"),
            disposition=_text(record, "row/policy_evaluated/disposition", "none"),
            dkim=_text(record, "row/policy_evaluated/dkim", "unknown"),
            spf=_text(record, "row/policy_evaluated/spf", "unknown"),
            header_from=_text(record, "identifiers/header_from"),
            envelope_from=_text(record, "identifiers/envelope_from"),
            dkim_domains=", ".join(_text(item, "domain") for item in dkim_results if _text(item, "domain")),
            spf_domains=", ".join(_text(item, "domain") for item in spf_results if _text(item, "domain")),
        ))
    return rows


def parse_files(paths: Iterable[Path]) -> ParseResult:
    result = ParseResult()
    for path in paths:
        result.files_seen += 1
        try:
            for source_name, payload in _xml_payloads(path):
                try:
                    result.rows.extend(parse_xml(payload, source_name))
                    result.reports_parsed += 1
                except Exception as exc:
                    result.issues.append(ParseIssue(source_name, str(exc)))
        except (OSError, ValueError, zipfile.BadZipFile, gzip.BadGzipFile) as exc:
            result.issues.append(ParseIssue(path.name, str(exc)))
    return result

