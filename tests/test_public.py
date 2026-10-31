"""
Public tests for exercise-01: File Signature Forensics.

There are exactly 20 public tests: 2 per task.
Students should run them from the repository root with:

    python -m pytest -q tests/test_public.py

Hidden tests used by Classroom 50 should be kept outside the starter repository.
"""

import hashlib
import io
import json
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

import student


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _png_chunk(chunk_type: bytes, data: bytes = b"") -> bytes:
    """Create one valid PNG chunk."""
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return (
        struct.pack(">I", len(data))
        + chunk_type
        + data
        + struct.pack(">I", crc)
    )


def make_minimal_png() -> bytes:
    """Return a small, structurally valid 1x1 RGB PNG."""
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    # One scanline: filter byte + RGB pixel.
    raw_scanline = b"\x00\x00\x00\x00"
    idat = zlib.compress(raw_scanline)

    return (
        PNG_SIGNATURE
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", idat)
        + _png_chunk(b"IEND")
    )


def make_zip_bytes(member_name: str = "hello.txt", payload: bytes = b"hello") -> bytes:
    """Return a valid in-memory ZIP archive."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(member_name, payload)
    return buffer.getvalue()


def _signature_values():
    """Flatten SIGNATURES values into a list of bytes."""
    values = []
    for variants in student.SIGNATURES.values():
        if isinstance(variants, (bytes, bytearray)):
            values.append(bytes(variants))
        else:
            values.extend(bytes(v) for v in variants)
    return values


# ===========================================================================
# Task 1 — read_magic_bytes
# ===========================================================================

def test_task01_reads_only_requested_prefix(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"0123456789abcdef")

    assert student.read_magic_bytes(path, 5) == b"01234"


def test_task01_short_file_is_returned_without_crashing(tmp_path):
    path = tmp_path / "short.bin"
    path.write_bytes(b"\x00\x01\x02")

    assert student.read_magic_bytes(path, 16) == b"\x00\x01\x02"


# ===========================================================================
# Task 2 — SIGNATURES
# ===========================================================================

def test_task02_signatures_has_at_least_12_formats_and_byte_variants():
    assert isinstance(student.SIGNATURES, dict)
    assert len(student.SIGNATURES) >= 12

    for name, variants in student.SIGNATURES.items():
        assert isinstance(name, str) and name
        assert isinstance(variants, (list, tuple))
        assert variants, f"{name} must contain at least one signature"
        assert all(isinstance(v, bytes) and v for v in variants)


def test_task02_signatures_include_core_shared_and_jpeg_formats():
    names = {name.upper() for name in student.SIGNATURES}

    # These names are part of the public assignment contract.
    for required in {"PNG", "PDF", "JPEG", "DOCX", "XLSX", "PPTX", "JAR"}:
        assert required in names, f"Missing SIGNATURES entry for {required}"

    all_sigs = _signature_values()

    assert any(sig.startswith(PNG_SIGNATURE) for sig in all_sigs)
    assert any(sig.startswith(b"%PDF-") for sig in all_sigs)

    jpeg_variants = {sig[:4] for sig in all_sigs if sig.startswith(b"\xff\xd8\xff")}
    assert len(jpeg_variants) >= 2, "Include at least two JPEG header variants"

    for name in ("DOCX", "XLSX", "PPTX", "JAR"):
        variants = student.SIGNATURES[name]
        assert any(v.startswith(b"PK\x03\x04") for v in variants)


# ===========================================================================
# Task 3 — identify_file_type
# ===========================================================================

def test_task03_identifies_common_formats_and_unknown():
    assert student.identify_file_type(PNG_SIGNATURE + b"\x00" * 20) == "PNG"
    assert student.identify_file_type(b"%PDF-1.7\nrest") == "PDF"
    assert student.identify_file_type(b"\x01\x02") == "unknown"


def test_task03_disambiguates_zip_family_from_secondary_bytes():
    cases = {
        "DOCX": b"PK\x03\x04" + b"\x00" * 20 + b"word/document.xml",
        "XLSX": b"PK\x03\x04" + b"\x00" * 20 + b"xl/workbook.xml",
        "PPTX": b"PK\x03\x04" + b"\x00" * 20 + b"ppt/presentation.xml",
        "JAR": b"PK\x03\x04" + b"\x00" * 20 + b"META-INF/MANIFEST.MF",
    }

    for expected, magic in cases.items():
        assert student.identify_file_type(magic) == expected


# ===========================================================================
# Task 4 — checksums and integrity
# ===========================================================================

def test_task04_compute_checksum_matches_hashlib(tmp_path):
    path = tmp_path / "data.bin"
    data = b"APDR\x00file-signature-forensics\n"
    path.write_bytes(data)

    expected = hashlib.sha256(data).hexdigest()
    assert student.compute_checksum(path) == expected


def test_task04_verify_integrity_accepts_match_and_rejects_mismatch(tmp_path):
    path = tmp_path / "data.bin"
    data = b"integrity-test"
    path.write_bytes(data)

    good = hashlib.sha256(data).hexdigest()
    bad = "0" * 64

    assert student.verify_integrity(path, good) is True
    assert student.verify_integrity(path, bad) is False


# ===========================================================================
# Task 5 — find_mismatched_extensions
# ===========================================================================

def test_task05_finds_mismatch_recursively(tmp_path):
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)

    spoofed = nested / "invoice.txt"
    spoofed.write_bytes(make_minimal_png())

    result = student.find_mismatched_extensions(tmp_path)

    assert isinstance(result, list)
    matches = [item for item in result if Path(item["path"]).name == "invoice.txt"]
    assert len(matches) == 1

    item = matches[0]
    assert set(item) >= {"path", "claimed_type", "actual_type"}
    assert str(item["actual_type"]).upper() == "PNG"


def test_task05_does_not_report_correct_png_extension(tmp_path):
    good = tmp_path / "image.png"
    good.write_bytes(make_minimal_png())

    result = student.find_mismatched_extensions(tmp_path)

    assert all(Path(item["path"]).name != "image.png" for item in result)


# ===========================================================================
# Task 6 — detect_polyglot
# ===========================================================================

def test_task06_single_format_returns_one_matching_type(tmp_path):
    path = tmp_path / "only.png"
    path.write_bytes(make_minimal_png())

    result = student.detect_polyglot(path)

    assert isinstance(result, list)
    assert "PNG" in result
    assert len(set(result)) == 1


def test_task06_detects_file_with_pdf_and_zip_signatures(tmp_path):
    # A ZIP archive can legally have bytes before its first local-file header.
    # This sample therefore contains a PDF header plus a valid ZIP archive.
    pdf_prefix = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n"
    path = tmp_path / "polyglot.bin"
    path.write_bytes(pdf_prefix + make_zip_bytes())

    result = student.detect_polyglot(path)
    upper = {name.upper() for name in result}

    assert "PDF" in upper
    assert any(name in upper for name in {"ZIP", "ZIP_FAMILY"})


# ===========================================================================
# Task 7 — bytes_to_hexdump
# ===========================================================================

def test_task07_hexdump_exact_full_line():
    data = b"ABCD"

    expected = "00000000  41 42 43 44  |ABCD|"
    assert student.bytes_to_hexdump(data, width=4) == expected


def test_task07_hexdump_exact_partial_line_and_ascii_replacement():
    data = b"ABC\x00Z"

    expected = (
        "00000000  41 42 43 00  |ABC.|\n"
        "00000004  5A           |Z|"
    )
    assert student.bytes_to_hexdump(data, width=4) == expected


# ===========================================================================
# Task 8 — detect_text_encoding
# ===========================================================================

def test_task08_detects_ascii_and_utf8(tmp_path):
    ascii_file = tmp_path / "ascii.txt"
    ascii_file.write_bytes(b"plain ASCII text\n")

    utf8_file = tmp_path / "utf8.txt"
    utf8_file.write_bytes("Grüße aus Erlangen".encode("utf-8"))

    assert student.detect_text_encoding(ascii_file) == "ASCII"
    assert student.detect_text_encoding(utf8_file) == "UTF-8"


def test_task08_detects_utf16_boms(tmp_path):
    le = tmp_path / "le.txt"
    le.write_bytes(b"\xff\xfe" + "Hello".encode("utf-16-le"))

    be = tmp_path / "be.txt"
    be.write_bytes(b"\xfe\xff" + "Hello".encode("utf-16-be"))

    assert student.detect_text_encoding(le) == "UTF-16-LE"
    assert student.detect_text_encoding(be) == "UTF-16-BE"


# ===========================================================================
# Task 9 — find_appended_data
# ===========================================================================

def test_task09_returns_none_when_png_ends_at_iend(tmp_path):
    png = make_minimal_png()
    path = tmp_path / "clean.png"
    path.write_bytes(png)

    assert student.find_appended_data(path, "PNG") is None


def test_task09_returns_first_payload_offset_after_png_iend(tmp_path):
    png = make_minimal_png()
    payload = b"SECRET_PAYLOAD"
    path = tmp_path / "appended.png"
    path.write_bytes(png + payload)

    assert student.find_appended_data(path, "PNG") == len(png)


# ===========================================================================
# Task 10 — generate_forensics_report
# ===========================================================================

def test_task10_report_is_dict_and_json_serializable(tmp_path):
    (tmp_path / "clean.png").write_bytes(make_minimal_png())

    report = student.generate_forensics_report(tmp_path)

    assert isinstance(report, dict)
    # Must not raise TypeError.
    json.dumps(report)


def test_task10_report_aggregates_findings_from_nested_files(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()

    spoofed = nested / "spoofed.txt"
    spoofed.write_bytes(make_minimal_png())

    appended = nested / "payload.png"
    appended.write_bytes(make_minimal_png() + b"PAYLOAD")

    report = student.generate_forensics_report(tmp_path)
    serialized = json.dumps(report)

    # We deliberately do not prescribe exact top-level key names here.
    # The report must, however, aggregate findings for these suspicious files.
    assert "spoofed.txt" in serialized
    assert "payload.png" in serialized
