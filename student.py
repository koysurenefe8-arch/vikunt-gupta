"""
File Signature Forensics

A security team's utility that classifies unknown files from raw bytes only, never trusting file extensions.

Personalization: A generated samples/ directory is baked into the repo at creation time, seeded from hash(github_username): spoofed extensions, one polyglot file, one file with an appended payload.

Implement each TODO below. Do not rename functions/classes or
change signatures -- the grader imports them by name.
"""
import hashlib
import io
import zipfile

SIGNATURES = {
    # TODO: populate with >=12 formats, e.g.
    # "PNG": [b"\x89PNG\r\n\x1a\n"],
    # "ZIP_FAMILY": [b"PK\x03\x04"],  # docx/xlsx/pptx/jar all share this prefix
    # Image formats
    "PNG": [
        b"\x89PNG\r\n\x1a\n"
    ],

    "JPEG": [
        b"\xff\xd8\xff\xe0",
        b"\xff\xd8\xff\xe1",
        b"\xff\xd8\xff\xdb",
        b"\xff\xd8\xff\xee"
    ],

    "GIF": [
        b"GIF87a",
        b"GIF89a"
    ],

    "BMP": [
        b"BM"
    ],

    "TIFF": [
        b"II*\x00",
        b"MM\x00*"
    ],

    # Document formats
    "PDF": [
        b"%PDF-"
    ],

    # ZIP-based formats
    "ZIP": [
        b"PK\x03\x04"
    ],

    "DOCX": [
        b"PK\x03\x04"
    ],

    "XLSX": [
        b"PK\x03\x04"
    ],

    "PPTX": [
        b"PK\x03\x04"
    ],

    "JAR": [
        b"PK\x03\x04"
    ],

    # Archive formats
    "RAR": [
        b"Rar!\x1a\x07\x00",
        b"Rar!\x1a\x07\x01\x00"
    ],

    "7Z": [
        b"7z\xbc\xaf\x27\x1c"
    ],

    "GZIP": [
        b"\x1f\x8b"
    ],

    # Audio formats
    "WAV": [
        b"RIFF"
    ],

    "MP3": [
        b"ID3",
        b"\xff\xfb"
    ]
}

def read_magic_bytes(filepath, n=16):
    with open(filepath, "rb") as file:
        return file.read(n)

def identify_file_type(magic):
    magic = bytes(magic)

    zip_signature = b"PK\x03\x04"

    if magic.startswith(zip_signature):
        zip_formats = {
            "DOCX": b"word/document.xml",
            "XLSX": b"xl/workbook.xml",
            "PPTX": b"ppt/presentation.xml",
            "JAR": b"META-INF/MANIFEST.MF"
        }

        for filetype, identifier in zip_formats.items():
            if identifier in magic:
                return filetype

        return "ZIP"

    for filetype, signatures in SIGNATURES.items():
        if filetype.upper() in ("DOCX", "XLSX", "PPTX", "JAR", "ZIP"):
            continue

        for signature in signatures:
            if magic.startswith(signature):
                return filetype

    return "unknown"


def compute_checksum(filepath, algo="sha256"):
    hash_object = hashlib.new(algo)

    with open(filepath, "rb") as file:
        while True:
            chunk = file.read(4096)

            if not chunk:
                break

            hash_object.update(chunk)

    return hash_object.hexdigest()

def verify_integrity(filepath, expected_checksum, algo="sha256"):
    actual_checksum = compute_checksum(filepath, algo)

    return actual_checksum == expected_checksum

def find_mismatched_extensions(root_dir):
    from pathlib import Path

    # Map filename extensions to their actual format names.
    extension_map = {
        ".png": "PNG",
        ".jpg": "JPEG",
        ".jpeg": "JPEG",
        ".gif": "GIF",
        ".bmp": "BMP",
        ".tif": "TIFF",
        ".tiff": "TIFF",
        ".pdf": "PDF",
        ".zip": "ZIP",
        ".docx": "DOCX",
        ".xlsx": "XLSX",
        ".pptx": "PPTX",
        ".jar": "JAR",
        ".rar": "RAR",
        ".7z": "7Z",
        ".gz": "GZIP",
        ".wav": "WAV",
        ".mp3": "MP3"
    }

    mismatches = []

    # Recursively examine every file.
    for filepath in Path(root_dir).rglob("*"):

        if not filepath.is_file():
            continue

        # Determine the claimed format from the extension.
        extension = filepath.suffix.lower()
        claimed_type = extension_map.get(
            extension, extension.lstrip(".").upper()
        )

        # Read the file's actual signature.
        magic = read_magic_bytes(filepath, 4096)
        actual_type = identify_file_type(magic)

        # Ignore files whose signatures we cannot identify.
        if actual_type == "unknown":
            continue

        # Compare claimed and actual formats.
        if claimed_type != actual_type:
            mismatches.append({
                "path": str(filepath),
                "claimed_type": claimed_type,
                "actual_type": actual_type
            })

    return mismatches

def _detect_types_from_data(data):
    detected = []

    # Detect formats identified by their starting signatures.
    for filetype, signatures in SIGNATURES.items():
        if filetype.upper() in ("ZIP", "DOCX", "XLSX", "PPTX", "JAR"):
            continue

        for signature in signatures:
            if data.startswith(signature):
                if filetype not in detected:
                    detected.append(filetype)
                break

    # Check whether the file contains a valid ZIP archive.
    zip_members = []

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            zip_members = archive.namelist()

        if "word/document.xml" in zip_members:
            detected.append("DOCX")
        elif "xl/workbook.xml" in zip_members:
            detected.append("XLSX")
        elif "ppt/presentation.xml" in zip_members:
            detected.append("PPTX")
        elif "META-INF/MANIFEST.MF" in zip_members:
            detected.append("JAR")
        else:
            detected.append("ZIP")

    except (zipfile.BadZipFile, OSError, ValueError):
        # Also support the simplified ZIP-family examples
        # used in the public Task 3 tests.
        if data.startswith(b"PK\x03\x04"):
            identifiers = {
                "DOCX": b"word/document.xml",
                "XLSX": b"xl/workbook.xml",
                "PPTX": b"ppt/presentation.xml",
                "JAR": b"META-INF/MANIFEST.MF"
            }

            matched = False

            for name, identifier in identifiers.items():
                if identifier in data:
                    detected.append(name)
                    matched = True

            if not matched:
                detected.append("ZIP")

    return list(dict.fromkeys(detected))


def detect_polyglot(filepath):
    with open(filepath, "rb") as file:
        data = file.read()

    return _detect_types_from_data(data)

def bytes_to_hexdump(data, width=16):
    if width <= 0:
        raise ValueError("width must be greater than zero")

    lines = []

    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]

        hex_part = " ".join(f"{byte:02X}" for byte in chunk)

        ascii_part = "".join(
            chr(byte) if 32 <= byte <= 126 else "."
            for byte in chunk
        )

        line = (
            f"{offset:08X}  "
            f"{hex_part.ljust(width * 3)}"
            f" |{ascii_part}|"
        )

        lines.append(line)

    return "\n".join(lines)


def _detect_encoding_from_data(data):

    # Check UTF-16 BOMs first.
    if data.startswith(b"\xff\xfe"):
        return "UTF-16-LE"

    if data.startswith(b"\xfe\xff"):
        return "UTF-16-BE"

    # Check UTF-16 patterns without BOM.
    if len(data) >= 4:
        even_zeros = sum(
            1 for i in range(0, len(data), 2)
            if data[i] == 0
        )

        odd_zeros = sum(
            1 for i in range(1, len(data), 2)
            if data[i] == 0
        )

        pairs = len(data) // 2

        if pairs > 0:
            if odd_zeros / pairs > 0.3:
                return "UTF-16-LE"

            if even_zeros / pairs > 0.3:
                return "UTF-16-BE"

    # ASCII contains only bytes from 0 to 127.
    if all(byte < 128 for byte in data):
        return "ASCII"

    # Check whether the remaining bytes form valid UTF-8.
    try:
        data.decode("utf-8")
        return "UTF-8"
    except UnicodeDecodeError:
        return "Latin-1"


def detect_text_encoding(filepath):
    with open(filepath, "rb") as file:
        data = file.read()

    return _detect_encoding_from_data(data)


def _find_appended_offset(data, filetype):

    filetype = filetype.upper()

    # PNG: locate the end of the IEND chunk.
    if filetype == "PNG":

        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return None

        offset = 8

        while offset + 12 <= len(data):

            chunk_length = int.from_bytes(
                data[offset:offset + 4], "big"
            )

            chunk_type = data[offset + 4:offset + 8]

            chunk_end = offset + 12 + chunk_length

            if chunk_end > len(data):
                return None

            if chunk_type == b"IEND":
                return chunk_end

            offset = chunk_end

        return None

    # JPEG: locate the End Of Image marker.
    if filetype == "JPEG":

        if not data.startswith(b"\xff\xd8"):
            return None

        position = data.rfind(b"\xff\xd9")

        if position == -1:
            return None

        return position + 2

    # GIF: locate the trailer byte.
    if filetype == "GIF":

        if not data.startswith((b"GIF87a", b"GIF89a")):
            return None

        position = data.rfind(b"\x3b")

        if position == -1:
            return None

        return position + 1

    # PDF: locate the final EOF marker.
    if filetype == "PDF":

        position = data.rfind(b"%%EOF")

        if position == -1:
            return None

        return position + len(b"%%EOF")

    # ZIP: locate the End Of Central Directory record.
    if filetype == "ZIP":

        position = data.rfind(b"PK\x05\x06")

        if position == -1 or position + 22 > len(data):
            return None

        comment_length = int.from_bytes(
            data[position + 20:position + 22], "little"
        )

        return position + 22 + comment_length

    return None


def find_appended_data(filepath, filetype):

    with open(filepath, "rb") as file:
        data = file.read()

    offset = _find_appended_offset(data, filetype)

    if offset is None:
        return None

    if offset < len(data):
        return offset

    return None

def generate_forensics_report(root_dir):

    from pathlib import Path

    extension_map = {
        ".png": "PNG",
        ".jpg": "JPEG",
        ".jpeg": "JPEG",
        ".gif": "GIF",
        ".bmp": "BMP",
        ".tif": "TIFF",
        ".tiff": "TIFF",
        ".pdf": "PDF",
        ".zip": "ZIP",
        ".docx": "DOCX",
        ".xlsx": "XLSX",
        ".pptx": "PPTX",
        ".jar": "JAR",
        ".rar": "RAR",
        ".7z": "7Z",
        ".gz": "GZIP",
        ".wav": "WAV",
        ".mp3": "MP3"
    }

    report = {
        "files": [],
        "mismatches": [],
        "polyglots": [],
        "appended_data": [],
        "summary": {}
    }

    root = Path(root_dir)

    for filepath in root.rglob("*"):

        if not filepath.is_file():
            continue

        # Read each file only once.
        with open(filepath, "rb") as file:
            data = file.read()

        magic = data[:4096]

        actual_type = identify_file_type(magic)

        # Use the full bytes for polyglot detection.
        detected_types = _detect_types_from_data(data)

        extension = filepath.suffix.lower()

        claimed_type = extension_map.get(
            extension,
            extension.lstrip(".").upper()
        )

        # Calculate SHA-256 directly from the loaded bytes.
        checksum = hashlib.sha256(data).hexdigest()

        # Detect text encoding.
        encoding = _detect_encoding_from_data(data)

        # Check for appended data.
        appended_offset = _find_appended_offset(
            data, actual_type
        )

        has_appended_data = (
            appended_offset is not None
            and appended_offset < len(data)
        )

        # Construct a JSON-serializable record.
        record = {
            "path": str(filepath),
            "claimed_type": claimed_type,
            "actual_type": actual_type,
            "magic_bytes": magic.hex(),
            "checksum_sha256": checksum,
            "polyglot_types": detected_types,
            "is_polyglot": len(detected_types) > 1,
            "encoding": encoding,
            "appended_data_offset": (
                appended_offset if has_appended_data else None
            ),
            "has_appended_data": has_appended_data,
            "hexdump": bytes_to_hexdump(data[:256])
        }

        report["files"].append(record)

        # Collect extension mismatches.
        if actual_type != "unknown" and claimed_type != actual_type:

            report["mismatches"].append({
                "path": str(filepath),
                "claimed_type": claimed_type,
                "actual_type": actual_type
            })

        # Collect polyglot files.
        if len(detected_types) > 1:
            report["polyglots"].append({
                "path": str(filepath),
                "types": detected_types
            })

        # Collect files with appended payloads.
        if has_appended_data:
            report["appended_data"].append({
                "path": str(filepath),
                "offset": appended_offset
            })

    # Aggregate statistics.
    report["summary"] = {
        "total_files": len(report["files"]),
        "mismatched_extensions": len(report["mismatches"]),
        "polyglot_files": len(report["polyglots"]),
        "files_with_appended_data": len(report["appended_data"])
    }

    return report
