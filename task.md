# exercise-01: File Signature Forensics

**Type:** B (script, student.py)
**Lecture mapping:** 02_computers, 03_data_representation
**Scoring:** 10 tasks x 4 pts (2 visible + 2 hidden) = 40 pts

## Scenario
A security team's utility that classifies unknown files from raw bytes only, never trusting file extensions.

## Personalization
A generated samples/ directory is baked into the repo at creation time, seeded from hash(github_username): spoofed extensions, one polyglot file, one file with an appended payload.

## Tasks
1. `read_magic_bytes(filepath, n=16)` -- read only the first n bytes; never load the whole file.
2. `SIGNATURES` table covering >=12 formats including shared-prefix formats (ZIP-based docx/xlsx/pptx/jar) and multi-variant JPEG headers.
3. `identify_file_type(magic)` -- disambiguate shared-prefix formats via secondary bytes; `"unknown"` on no match; must not crash on files shorter than n.
4. `compute_checksum(filepath, algo="sha256")` / `verify_integrity(filepath, expected)`.
5. `find_mismatched_extensions(root_dir)` -- recurse to arbitrary depth.
6. `detect_polyglot(filepath)` -- return every type the file validly matches; >1 means polyglot.
7. `bytes_to_hexdump(data, width=16)` -- exact canonical `offset | hex | ascii` format, deterministic and diffable.
8. `detect_text_encoding(filepath)` -- distinguish UTF-8 / UTF-16-LE(+BOM) / UTF-16-BE(+BOM) / ASCII / Latin-1 from byte patterns only; no `chardet`, no `codecs` auto-detect.
9. `find_appended_data(filepath, filetype)` -- byte offset where the legitimate structure ends (e.g. after PNG `IEND`); flags trailing bytes.
10. `generate_forensics_report(root_dir)` -- JSON-serializable aggregate of 1-9; must complete on 500+ files within a stated time budget.

See `student.py` for full docstrings and exact function/class signatures.
Do not rename functions/classes -- the grader imports them by name.

## Written justification
Using your own samples/ directory's actual byte offsets, explain how you identified the polyglot file and the exact offset of the appended payload.

## Submission
Push to GitHub Classroom. CI (`.github/workflows/classroom.yml`) runs the
visible structural test suite automatically; hidden tests run after the
deadline from the private `hidden-tests` repository.

## Status
Scaffold generated automatically by `generate_exercises.py`. The visible
`grader/tests.py` and private hidden-test stubs contain STRUCTURAL checks
only -- add real correctness assertions once a verified reference solution
exists for each task. Personalization (seeded datasets / bug placement)
needs to be wired into repo creation before live grading; this scaffold
ships static example data/bugs where relevant.
