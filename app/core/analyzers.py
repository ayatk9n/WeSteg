# WeSteg - Steganalysis & Carving Engines

import hashlib
import os
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
import numpy as np
from PIL import Image, ExifTags

from app.core.bitplanes import MAX_FORENSIC_PIXELS
from app.core.encoders_lsb import extract_lsb_data
from app.core.encoders_meta import parse_png_chunks, detect_eof_trailing_data

MAX_STRINGS_SCAN_BYTES = 32 * 1024 * 1024
MAX_CARVE_SCAN_BYTES = 128 * 1024 * 1024
MAX_SINGLE_CARVE_BYTES = 64 * 1024 * 1024
MAX_NATIVE_CARVES = 15
MAX_CLI_ARTIFACTS = 25


@dataclass
class ExtractedArtifact:
    name: str
    path: str
    size: int
    source_tool: str
    description: str = ""


@dataclass
class AnalyzerResult:
    tool_id: str
    title: str
    status: str
    badge_text: str
    output_text: str
    command_run: str = ""
    artifacts: List[ExtractedArtifact] = field(default_factory=list)


MAGIC_SIGNATURES = [
    ("zip", b"PK\x03\x04", "ZIP Archive / Office Document", ".zip"),
    ("rar", b"Rar!\x1a\x07", "RAR Archive", ".rar"),
    ("gzip", b"\x1f\x8b\x08", "GZIP Compressed Data", ".gz"),
    ("bzip2", b"BZh", "BZIP2 Compressed Data", ".bz2"),
    ("7z", b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", ".7z"),
    ("pdf", b"%PDF-", "PDF Document", ".pdf"),
    ("png", b"\x89PNG\r\n\x1a\n", "Embedded PNG Image", ".png"),
    ("jpeg_jfif", b"\xff\xd8\xff\xe0", "Embedded JPEG Image (JFIF)", ".jpg"),
    ("jpeg_exif", b"\xff\xd8\xff\xe1", "Embedded JPEG Image (EXIF)", ".jpg"),
    ("gif", b"GIF89a", "Embedded GIF89a Image", ".gif"),
    ("elf", b"\x7fELF", "Linux ELF Executable", ".elf"),
    ("riff", b"RIFF", "RIFF Container (WAV/AVI/WebP)", ".riff"),
    ("ogg", b"OggS", "Ogg Multimedia Container", ".ogg"),
]


def _validate_and_bound_carve(raw: bytes, idx: int, sig_id: str) -> Optional[Tuple[int, str]]:
    n = len(raw)
    rem = n - idx

    if sig_id == "zip":
        if rem < 30:
            return None
        ver, _flags, comp_method = struct.unpack("<HHH", raw[idx + 4 : idx + 10])
        fname_len, extra_len = struct.unpack("<HH", raw[idx + 26 : idx + 30])
        if ver > 100 or comp_method not in (0, 8, 9, 12, 14, 99) or fname_len == 0 or fname_len > 512:
            return None
        if idx + 30 + fname_len + extra_len > n:
            return None
        eocd = raw.find(b"PK\x05\x06", idx + 30)
        if eocd != -1 and eocd + 22 <= n:
            comment_len = struct.unpack("<H", raw[eocd + 20 : eocd + 22])[0]
            end_pos = min(n, eocd + 22 + comment_len)
            return end_pos, ".zip"
        return min(n, idx + MAX_SINGLE_CARVE_BYTES), ".zip"

    if sig_id == "bzip2":
        if rem < 10:
            return None
        if not (ord("1") <= raw[idx + 3] <= ord("9")):
            return None
        if raw[idx + 4 : idx + 10] != b"\x31\x41\x59\x26\x53\x59":
            return None
        return min(n, idx + MAX_SINGLE_CARVE_BYTES), ".bz2"

    if sig_id == "gzip":
        if rem < 18:
            return None
        flg = raw[idx + 3]
        xfl = raw[idx + 8]
        if (flg & 0xE0) != 0 or xfl not in (0, 2, 4):
            return None
        return min(n, idx + MAX_SINGLE_CARVE_BYTES), ".gz"

    if sig_id == "png":
        if rem < 33 or raw[idx + 8 : idx + 16] != b"\x00\x00\x00\rIHDR":
            return None
        iend_pos = raw.find(b"\x00\x00\x00\x00IEND\xaeB`\x82", idx + 16)
        if iend_pos != -1:
            return iend_pos + 12, ".png"
        return min(n, idx + MAX_SINGLE_CARVE_BYTES), ".png"

    if sig_id in ("jpeg_jfif", "jpeg_exif"):
        if rem < 20:
            return None
        seg_len = struct.unpack(">H", raw[idx + 4 : idx + 6])[0]
        ident = raw[idx + 6 : idx + 11]
        if seg_len < 8 or not (ident.startswith(b"JFIF\x00") or ident.startswith(b"Exif\x00") or ident.startswith(b"http")):
            return None
        return min(n, idx + MAX_SINGLE_CARVE_BYTES), ".jpg"

    if sig_id == "pdf":
        if rem < 16 or not re.match(rb"%PDF-[12]\.[0-9]", raw[idx : idx + 8]):
            return None
        eof_marker = raw.find(b"%%EOF", idx + 8)
        if eof_marker != -1:
            return min(n, eof_marker + 7), ".pdf"
        return min(n, idx + MAX_SINGLE_CARVE_BYTES), ".pdf"

    if sig_id == "elf":
        if rem < 52:
            return None
        if raw[idx + 4] not in (1, 2) or raw[idx + 5] not in (1, 2) or raw[idx + 6] != 1:
            return None
        return min(n, idx + MAX_SINGLE_CARVE_BYTES), ".elf"

    if sig_id == "riff":
        if rem < 12:
            return None
        riff_size = struct.unpack("<I", raw[idx + 4 : idx + 8])[0]
        sub_fmt = raw[idx + 8 : idx + 12]
        fmt_map = {b"WAVE": ".wav", b"AVI ": ".avi", b"WEBP": ".webp"}
        if sub_fmt not in fmt_map or riff_size < 4:
            return None
        end_pos = min(n, idx + 8 + riff_size, idx + MAX_SINGLE_CARVE_BYTES)
        return end_pos, fmt_map[sub_fmt]

    if sig_id == "ogg":
        if rem < 28 or raw[idx + 4] != 0x00 or raw[idx + 5] > 0x07:
            return None
        return min(n, idx + MAX_SINGLE_CARVE_BYTES), ".ogg"

    if sig_id == "gif":
        if rem < 14:
            return None
        return min(n, idx + MAX_SINGLE_CARVE_BYTES), ".gif"

    ext = ".rar" if sig_id == "rar" else ".7z"
    return min(n, idx + MAX_SINGLE_CARVE_BYTES), ext


def _collect_safe_cli_artifacts(
    search_dir: str,
    workspace_dir: str,
    source_label: str,
    source_file_size: int,
    existing_artifacts: List[ExtractedArtifact],
) -> List[ExtractedArtifact]:
    found: List[ExtractedArtifact] = []
    if not os.path.isdir(search_dir):
        return found

    real_workspace = os.path.realpath(workspace_dir)
    seen_paths = {os.path.realpath(a.path) for a in existing_artifacts}

    for root, dirs, files in os.walk(search_dir, followlinks=False):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
        for fn in sorted(files):
            if fn == "audit.txt":
                continue
            full_p = os.path.join(root, fn)
            if os.path.islink(full_p):
                continue
            real_p = os.path.realpath(full_p)
            if not real_p.startswith(real_workspace + os.sep):
                continue
            if real_p in seen_paths:
                continue
            try:
                sz = os.path.getsize(real_p)
            except OSError:
                continue
            if sz == 0 or (sz == source_file_size and fn.startswith("00000000")):
                continue

            seen_paths.add(real_p)
            rel_name = os.path.relpath(real_p, search_dir).replace("\\", "/")
            found.append(
                ExtractedArtifact(
                    name=f"{source_label.lower()}_{os.path.basename(fn)}",
                    path=real_p,
                    size=sz,
                    source_tool=source_label,
                    description=f"Extracted file ({rel_name})",
                )
            )
            if len(found) >= MAX_CLI_ARTIFACTS:
                return found
    return found


def run_file_and_hashes(file_path: str) -> AnalyzerResult:
    abs_path = os.path.abspath(file_path)
    size = os.path.getsize(abs_path)

    md5_h = hashlib.md5()
    sha1_h = hashlib.sha1()
    sha256_h = hashlib.sha256()

    with open(abs_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            md5_h.update(chunk)
            sha1_h.update(chunk)
            sha256_h.update(chunk)

    lines = [
        f"File Name   : {os.path.basename(abs_path)}",
        f"File Size   : {size:,} bytes ({size / 1024:.2f} KB)",
        f"MD5         : {md5_h.hexdigest()}",
        f"SHA-1       : {sha1_h.hexdigest()}",
        f"SHA-256     : {sha256_h.hexdigest()}",
    ]

    file_bin = shutil.which("file")
    if file_bin:
        try:
            proc = subprocess.run(
                [file_bin, "-b", "--", abs_path],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.stdout.strip():
                lines.append(f"libmagic    : {proc.stdout.strip()}")
        except Exception:
            pass

    try:
        with Image.open(abs_path) as img:
            lines.append(f"Format      : {img.format} ({img.format_description})")
            lines.append(f"Dimensions  : {img.width} x {img.height} px")
            lines.append(f"Color Mode  : {img.mode}")
            if getattr(img, "is_animated", False):
                lines.append(f"Frames      : {getattr(img, 'n_frames', 1)} (Animated)")
    except Exception as exc:
        lines.append(f"Image Parse : {exc}")

    return AnalyzerResult(
        tool_id="file_info",
        title="File & Image Properties (file / hashes / PIL)",
        status="info",
        badge_text=f"{size:,} B",
        output_text="\n".join(lines),
        command_run=f"file {os.path.basename(abs_path)} && sha256sum {os.path.basename(abs_path)}",
    )


def run_exiftool_analyzer(file_path: str) -> AnalyzerResult:
    abs_path = os.path.abspath(file_path)
    exiftool_bin = shutil.which("exiftool")
    if exiftool_bin:
        cmd = [exiftool_bin, "-a", "-u", "-g1", "--", abs_path]
        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=15,
            )
            out = (proc.stdout or proc.stderr).strip()
            suspicious = any(
                kw in out.lower()
                for kw in ("comment", "secret", "flag", "ctf", "password", "artist", "copyright", "warning")
            )
            return AnalyzerResult(
                tool_id="exiftool",
                title="ExifTool Metadata Inspector",
                status="hit" if suspicious else "info",
                badge_text="Metadata Found" if suspicious else "Standard Metadata",
                output_text=out,
                command_run=f"exiftool -a -u -g1 {os.path.basename(abs_path)}",
            )
        except Exception:
            pass

    lines = ["[Native Python Metadata Engine (ExifTool fallback)]"]
    found_custom = False
    try:
        with Image.open(abs_path) as img:
            if img.info:
                for k, v in img.info.items():
                    if k in ("exif", "icc_profile"):
                        lines.append(f"{k:<22}: <{len(v) if isinstance(v, (bytes, bytearray)) else '?'} bytes>")
                        continue
                    found_custom = True
                    lines.append(f"{str(k):<22}: {repr(v)[:300]}")
            exif_data = img.getexif()
            if exif_data:
                for tag_id, val in exif_data.items():
                    tag_name = ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")
                    found_custom = True
                    lines.append(f"{str(tag_name):<22}: {str(val)[:300]}")
                ifd = exif_data.get_ifd(0x8769)
                for tag_id, val in ifd.items():
                    tag_name = ExifTags.TAGS.get(tag_id, f"ExifTag_{tag_id}")
                    found_custom = True
                    val_str = val.decode("utf-8", errors="replace") if isinstance(val, bytes) else str(val)
                    lines.append(f"{str(tag_name):<22}: {val_str[:300]}")
    except Exception as exc:
        lines.append(f"Error reading metadata: {exc}")

    if len(lines) == 1:
        lines.append("No custom EXIF or text metadata tags found.")

    return AnalyzerResult(
        tool_id="exiftool",
        title="ExifTool / Metadata Inspector",
        status="hit" if found_custom else "clean",
        badge_text="Custom Tags Found" if found_custom else "Clean",
        output_text="\n".join(lines),
        command_run=f"exiftool {os.path.basename(abs_path)}",
    )


def run_pngcheck_analyzer(file_path: str, workspace_dir: str) -> AnalyzerResult:
    abs_path = os.path.abspath(file_path)
    lines = []
    artifacts: List[ExtractedArtifact] = []
    status = "clean"
    badge = "OK"

    pngcheck_bin = shutil.which("pngcheck")
    if pngcheck_bin and abs_path.lower().endswith(".png"):
        try:
            proc = subprocess.run(
                [pngcheck_bin, "-v", abs_path],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
            )
            lines.append("=== pngcheck -v Output ===")
            lines.append((proc.stdout + "\n" + proc.stderr).strip())
            lines.append("")
        except Exception:
            pass

    chunks, _ = parse_png_chunks(abs_path)
    if chunks:
        lines.append("=== PNG Chunk Structure Breakdown ===")
        lines.append(f"{'#':<4} {'Type':<6} {'Length':>10} {'CRC32':<12} {'Valid':<6} {'Decoded Preview'}")
        lines.append("-" * 78)
        for ch in chunks:
            if not ch.crc_valid or ch.chunk_type in ("tEXt", "zTXt", "iTXt") or ch.preview.startswith("Custom"):
                status = "hit"
                badge = f"Notable Chunk ({ch.chunk_type})"
            lines.append(
                f"{ch.index:<4} {ch.chunk_type:<6} {ch.length:>10,} {ch.crc_hex:<12} "
                f"{'OK' if ch.crc_valid else 'BAD!':<6} {ch.preview}"
            )

    eof_info = detect_eof_trailing_data(abs_path)
    if eof_info:
        marker_name, offset, trailing_bytes = eof_info
        status = "hit"
        badge = f"EOF Data ({len(trailing_bytes):,} B)"
        lines.append("")
        lines.append(
            f"[!] ALERT: {len(trailing_bytes):,} bytes of trailing data detected after {marker_name} at offset 0x{offset:X}!"
        )
        ascii_preview = "".join(chr(b) if 32 <= b < 127 else "." for b in trailing_bytes[:200])
        lines.append(f"ASCII Preview : {ascii_preview}")
        lines.append(f"Hex Preview   : {trailing_bytes[:64].hex(' ')}")

        ext = ".bin"
        for _, sig, _, sig_ext in MAGIC_SIGNATURES:
            if trailing_bytes.startswith(sig):
                ext = sig_ext
                break
        art_name = f"eof_trailing_payload{ext}"
        art_path = os.path.join(workspace_dir, art_name)
        saved_slice = trailing_bytes[:MAX_SINGLE_CARVE_BYTES]
        with open(art_path, "wb") as f:
            f.write(saved_slice)
        artifacts.append(
            ExtractedArtifact(
                name=art_name,
                path=art_path,
                size=len(saved_slice),
                source_tool="pngcheck / EOF Inspector",
                description=f"Appended after {marker_name} (offset 0x{offset:X})",
            )
        )

    if not lines:
        lines.append("Not a PNG image and no trailing EOF data detected after JPEG EOI.")

    return AnalyzerResult(
        tool_id="pngcheck",
        title="PNG Chunk & EOF Structure Inspector (pngcheck)",
        status=status,
        badge_text=badge,
        output_text="\n".join(lines),
        command_run=f"pngcheck -v {os.path.basename(abs_path)}",
        artifacts=artifacts,
    )


def run_zsteg_analyzer(
    file_path: str,
    workspace_dir: str,
    run_all: bool = False,
    password: str = "",
) -> AnalyzerResult:
    abs_path = os.path.abspath(file_path)
    lines = []
    artifacts: List[ExtractedArtifact] = []
    status = "clean"
    badge = "No LSB Hits"

    rgba_arr: Optional[np.ndarray] = None
    try:
        with Image.open(abs_path) as raw_img:
            if raw_img.width * raw_img.height <= MAX_FORENSIC_PIXELS:
                rgba_arr = np.array(raw_img.convert("RGBA"), dtype=np.uint8)
            else:
                lines.append("[!] Image exceeds pixel limit for in-memory native LSB scan.")
    except Exception:
        rgba_arr = None

    if rgba_arr is not None:
        configs = [
            (["R", "G", "B"], [0], "rgb_b0", "RGB Bit 0 (Standard LSB)"),
            (["R", "G", "B", "A"], [0], "rgba_b0", "RGBA Bit 0"),
            (["R"], [0], "r_b0", "Red Channel Bit 0"),
            (["G"], [0], "g_b0", "Green Channel Bit 0"),
            (["B"], [0], "b_b0", "Blue Channel Bit 0"),
            (["A"], [0], "a_b0", "Alpha Channel Bit 0"),
        ]
        lines.append("=== Native LSB & WeSteg Frame Scanner ===")
        for chs, bts, tag_prefix, label in configs:
            try:
                mode_desc, data, fname = extract_lsb_data(
                    abs_path,
                    channels=chs,
                    bits=bts,
                    password=password,
                    max_raw_bytes=512,
                    rgba_arr=rgba_arr,
                )
                if "Framed" in mode_desc or "AES-256-GCM" in mode_desc:
                    status = "hit"
                    badge = "LSB Payload Extracted!"
                    art_filename = f"lsb_{tag_prefix}_{fname}"
                    art_path = os.path.join(workspace_dir, art_filename)
                    with open(art_path, "wb") as f:
                        f.write(data)
                    artifacts.append(
                        ExtractedArtifact(
                            name=art_filename,
                            path=art_path,
                            size=len(data),
                            source_tool="zsteg / Native LSB",
                            description=f"{mode_desc} ({label})",
                        )
                    )
                    preview = data[:300].decode("utf-8", errors="replace")
                    lines.append(f"[+] {label} -> {mode_desc}: '{fname}' ({len(data):,} bytes)")
                    lines.append(f"    Preview: {preview}")
                else:
                    m = re.match(rb"^([\x20-\x7e\r\n\t]{6,240})", data)
                    if m:
                        status = "hit"
                        if badge == "No LSB Hits":
                            badge = "LSB ASCII Hit!"
                        txt = m.group(1).decode("ascii", errors="replace")
                        lines.append(f"[+] {label} -> Printable ASCII stream detected:")
                        lines.append(f'    "{txt}"')
            except ValueError as ve:
                if "Encrypted WeSteg" in str(ve) or "Invalid passphrase" in str(ve):
                    status = "hit"
                    badge = "Encrypted LSB Detected"
                    lines.append(f"[!] {label} -> {ve}")
            except Exception:
                pass

    zsteg_bin = shutil.which("zsteg")
    ext = os.path.splitext(abs_path)[1].lower()
    if zsteg_bin and ext in (".png", ".bmp"):
        cmd = [zsteg_bin] + (["-a"] if run_all else []) + [abs_path]
        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=45,
            )
            zout = (proc.stdout or proc.stderr).strip()
            lines.append("")
            lines.append(f"=== zsteg CLI Output ({'-a' if run_all else 'default'}) ===")
            lines.append(zout)
            if "text:" in zout or "file:" in zout or "zlib:" in zout:
                status = "hit"
                if badge == "No LSB Hits":
                    badge = "zsteg Hit"
        except Exception as exc:
            lines.append(f"\nzsteg execution error: {exc}")
    elif ext not in (".png", ".bmp"):
        lines.append("\n[Note: zsteg targets lossless PNG/BMP formats.]")
    elif not zsteg_bin:
        lines.append("\n[Note: Ruby `zsteg` CLI not installed; using Native Python LSB Scanner above.]")

    return AnalyzerResult(
        tool_id="zsteg",
        title="zsteg & Native LSB Bitstream Scanner",
        status=status,
        badge_text=badge,
        output_text="\n".join(lines),
        command_run=f"zsteg {'-a ' if run_all else ''}{os.path.basename(abs_path)}",
        artifacts=artifacts,
    )


def run_strings_analyzer(file_path: str, min_len: int = 5) -> AnalyzerResult:
    abs_path = os.path.abspath(file_path)
    file_size = os.path.getsize(abs_path)
    with open(abs_path, "rb") as f:
        raw = f.read(MAX_STRINGS_SCAN_BYTES)

    pattern = re.compile(rb"[\x20-\x7e]{" + str(max(3, int(min_len))).encode() + rb",}")
    matches = [m.group(0).decode("ascii", errors="replace") for m in pattern.finditer(raw)]

    interesting_re = re.compile(
        r"(flag\{.*?\}|ctf\{.*?\}|htb\{.*?\}|thm\{.*?\}|https?://\S+|pass(?:word)?\s*[:=]\s*\S+|secret\S*|\.zip|\.txt|\.png)",
        re.IGNORECASE,
    )
    highlights = [s[:300] for s in matches if interesting_re.search(s)]

    lines = [f"Total printable strings (len >= {min_len}): {len(matches):,}"]
    if file_size > MAX_STRINGS_SCAN_BYTES:
        lines.append(f"[Note: Scanned first {MAX_STRINGS_SCAN_BYTES // (1024 * 1024)} MB of {file_size:,} B file]")

    if highlights:
        lines.append("\n=== High-Interest Strings / Potential Flags ===")
        for h in highlights[:50]:
            lines.append(f"  [!] {h}")

    lines.append("\n=== Head (First 60 Strings) ===")
    lines.extend(f"  {s[:300]}" for s in matches[:60])

    if len(matches) > 60:
        lines.append(f"\n=== Tail (Last 60 Strings of {len(matches):,}) ===")
        lines.extend(f"  {s[:300]}" for s in matches[-60:])

    return AnalyzerResult(
        tool_id="strings",
        title="Strings & Pattern Extractor (strings)",
        status="hit" if highlights else "info",
        badge_text=f"{len(highlights)} Highlights" if highlights else f"{len(matches):,} Strings",
        output_text="\n".join(lines),
        command_run=f"strings -n {min_len} {os.path.basename(abs_path)}",
    )


def run_binwalk_foremost_analyzer(file_path: str, workspace_dir: str) -> AnalyzerResult:
    abs_path = os.path.abspath(file_path)
    source_size = os.path.getsize(abs_path)
    lines = []
    artifacts: List[ExtractedArtifact] = []
    status = "clean"
    badge = "No Embedded Files"

    with open(abs_path, "rb") as f:
        raw = f.read(MAX_CARVE_SCAN_BYTES)

    lines.append("=== Embedded Magic Signature Scan ===")
    carve_count = 0
    seen_offsets = set()

    for sig_id, sig, desc, _default_ext in MAGIC_SIGNATURES:
        start = 16
        while carve_count < MAX_NATIVE_CARVES:
            idx = raw.find(sig, start)
            if idx == -1:
                break
            start = idx + len(sig)
            if idx in seen_offsets:
                continue

            validated = _validate_and_bound_carve(raw, idx, sig_id)
            if validated is None:
                continue

            end_pos, refined_ext = validated
            seen_offsets.add(idx)
            carve_count += 1
            status = "hit"

            carved_bytes = raw[idx:end_pos]
            art_name = f"carved_0x{idx:X}{refined_ext}"
            art_path = os.path.join(workspace_dir, art_name)
            with open(art_path, "wb") as out_f:
                out_f.write(carved_bytes)
            artifacts.append(
                ExtractedArtifact(
                    name=art_name,
                    path=art_path,
                    size=len(carved_bytes),
                    source_tool="Signature Carver",
                    description=f"{desc} at offset 0x{idx:X} ({idx:,})",
                )
            )
            lines.append(
                f"[+] Offset 0x{idx:08X} ({idx:>10,}) : {desc} -> Carved as '{art_name}' ({len(carved_bytes):,} B)"
            )

    if carve_count == 0:
        lines.append("No secondary embedded file headers detected inside binary body.")

    binwalk_bin = shutil.which("binwalk") or shutil.which("binwalk3")
    if binwalk_bin:
        extract_dir = os.path.join(workspace_dir, "binwalk_out")
        os.makedirs(extract_dir, exist_ok=True)
        cmd = [binwalk_bin, "-e", "-C", extract_dir]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            try:
                help_proc = subprocess.run(
                    [binwalk_bin, "--help"],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                if "--run-as" in (help_proc.stdout + help_proc.stderr):
                    cmd.append("--run-as=root")
            except Exception:
                pass
        cmd.append(abs_path)

        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
            )
            lines.append(f"\n=== {os.path.basename(binwalk_bin)} CLI Output ===")
            lines.append((proc.stdout or proc.stderr).strip())
            bw_arts = _collect_safe_cli_artifacts(extract_dir, workspace_dir, "Binwalk", source_size, artifacts)
            if bw_arts:
                status = "hit"
                artifacts.extend(bw_arts)
        except Exception as exc:
            lines.append(f"\nbinwalk error: {exc}")

    foremost_bin = shutil.which("foremost")
    if foremost_bin:
        fm_dir = os.path.join(workspace_dir, "foremost_out")
        cmd = [foremost_bin, "-i", abs_path, "-o", fm_dir]
        try:
            subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if os.path.exists(fm_dir):
                audit_p = os.path.join(fm_dir, "audit.txt")
                if os.path.isfile(audit_p):
                    with open(audit_p, "r", errors="replace") as af:
                        lines.append("\n=== foremost audit.txt ===")
                        lines.append(af.read(16384).strip())
                fm_arts = _collect_safe_cli_artifacts(fm_dir, workspace_dir, "Foremost", source_size, artifacts)
                if fm_arts:
                    status = "hit"
                    artifacts.extend(fm_arts)
        except Exception:
            pass

    if artifacts:
        badge = f"{len(artifacts)} Carved File(s)"

    return AnalyzerResult(
        tool_id="binwalk",
        title="Binwalk & Foremost File Carver",
        status=status,
        badge_text=badge,
        output_text="\n".join(lines),
        command_run=f"binwalk -e {os.path.basename(abs_path)} && foremost -i {os.path.basename(abs_path)}",
        artifacts=artifacts,
    )


def run_steghide_analyzer(file_path: str, workspace_dir: str, password: str = "") -> AnalyzerResult:
    abs_path = os.path.abspath(file_path)
    steghide_bin = shutil.which("steghide")
    stegseek_bin = shutil.which("stegseek")
    ext = os.path.splitext(abs_path)[1].lower()
    masked_pw = "***" if password else ""

    if ext not in (".jpg", ".jpeg", ".bmp", ".wav", ".au"):
        return AnalyzerResult(
            tool_id="steghide",
            title="Steghide & Stegseek Extractor",
            status="clean",
            badge_text="N/A (Format)",
            output_text=f"Steghide supports JPEG, BMP, WAV, and AU formats (current file is '{ext}').",
            command_run=f"steghide extract -sf {os.path.basename(abs_path)}",
        )

    if not steghide_bin and not stegseek_bin:
        return AnalyzerResult(
            tool_id="steghide",
            title="Steghide & Stegseek Extractor",
            status="missing",
            badge_text="CLI Missing",
            output_text="Neither `steghide` nor `stegseek` is installed on system PATH.",
            command_run=f'steghide extract -sf {os.path.basename(abs_path)} -p "{masked_pw}"',
        )

    lines = []
    artifacts: List[ExtractedArtifact] = []
    status = "clean"
    badge = "No Payload"

    if steghide_bin:
        out_file = os.path.join(workspace_dir, "steghide_extracted.bin")
        cmd = [steghide_bin, "extract", "-sf", abs_path, "-xf", out_file, "-p", password, "-f"]
        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=20,
            )
            combined = (proc.stdout + "\n" + proc.stderr).strip()
            lines.append(f"=== steghide (passphrase: {'<provided>' if password else '<empty>'}) ===")
            lines.append(combined)
            if proc.returncode == 0 and os.path.isfile(out_file):
                status = "hit"
                badge = "Payload Extracted!"
                sz = os.path.getsize(out_file)
                with open(out_file, "rb") as f:
                    preview = f.read(300).decode("utf-8", errors="replace")
                lines.append(f"\n[+] Extracted Payload Preview ({sz:,} bytes):\n{preview}")
                artifacts.append(
                    ExtractedArtifact(
                        name="steghide_extracted.bin",
                        path=out_file,
                        size=sz,
                        source_tool="Steghide",
                        description="Extracted via steghide",
                    )
                )
        except Exception as exc:
            lines.append(f"Steghide error: {exc}")

    if stegseek_bin and status != "hit":
        seed_out = os.path.join(workspace_dir, "stegseek_seed_out.bin")
        cmd = [stegseek_bin, "--seed", "-sf", abs_path, "-xf", seed_out, "-f"]
        try:
            proc = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=20,
            )
            seed_text = (proc.stdout + "\n" + proc.stderr).strip()
            lines.append("\n=== stegseek --seed Output ===")
            lines.append(seed_text)
            if os.path.isfile(seed_out) and os.path.getsize(seed_out) > 0:
                status = "hit"
                badge = "Stegseek Seed Extracted!"
                sz = os.path.getsize(seed_out)
                artifacts.append(
                    ExtractedArtifact(
                        name="stegseek_seed_out.bin",
                        path=seed_out,
                        size=sz,
                        source_tool="Stegseek (--seed)",
                        description="Unencrypted payload recovered via Stegseek seed mode",
                    )
                )
            elif "Found steghide" in seed_text or "Encryption Algorithm" in seed_text:
                status = "hit"
                badge = "Steghide Detected!"
        except Exception:
            pass

        rockyou_path = "/usr/share/wordlists/rockyou.txt"
        if status != "hit" or badge == "Steghide Detected!":
            if os.path.isfile(rockyou_path):
                crack_out = os.path.join(workspace_dir, "stegseek_cracked.bin")
                crack_cmd = [stegseek_bin, "--crack", "-sf", abs_path, "-wl", rockyou_path, "-xf", crack_out, "-f"]
                try:
                    c_proc = subprocess.run(
                        crack_cmd,
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    c_text = (c_proc.stdout + "\n" + c_proc.stderr).strip()
                    lines.append("\n=== stegseek --crack (rockyou.txt) ===")
                    lines.append(c_text)
                    if c_proc.returncode == 0 and os.path.isfile(crack_out) and os.path.getsize(crack_out) > 0:
                        status = "hit"
                        badge = "Passphrase Cracked!"
                        sz = os.path.getsize(crack_out)
                        with open(crack_out, "rb") as cf:
                            preview = cf.read(300).decode("utf-8", errors="replace")
                        lines.append(f"\n[+] Cracked Payload Preview ({sz:,} bytes):\n{preview}")
                        artifacts.append(
                            ExtractedArtifact(
                                name="stegseek_cracked.bin",
                                path=crack_out,
                                size=sz,
                                source_tool="Stegseek (rockyou.txt)",
                                description="Cracked & extracted via rockyou.txt",
                            )
                        )
                except Exception:
                    pass

    return AnalyzerResult(
        tool_id="steghide",
        title="Steghide & Stegseek Extractor",
        status=status,
        badge_text=badge,
        output_text="\n".join(lines),
        command_run=f'steghide extract -sf {os.path.basename(abs_path)} -p "{masked_pw}"',
        artifacts=artifacts,
    )


def run_outguess_analyzer(file_path: str, workspace_dir: str, password: str = "") -> AnalyzerResult:
    abs_path = os.path.abspath(file_path)
    outguess_bin = shutil.which("outguess")
    ext = os.path.splitext(abs_path)[1].lower()
    masked_cmd = f"outguess {'-k \"***\" ' if password else ''}-r {os.path.basename(abs_path)} out.dat"

    if ext not in (".jpg", ".jpeg", ".ppm", ".pnm"):
        return AnalyzerResult(
            tool_id="outguess",
            title="OutGuess JPEG Extractor",
            status="clean",
            badge_text="N/A (Format)",
            output_text=f"OutGuess targets JPEG/PPM/PNM images (current file is '{ext}').",
            command_run=masked_cmd,
        )

    if not outguess_bin:
        return AnalyzerResult(
            tool_id="outguess",
            title="OutGuess JPEG Extractor",
            status="missing",
            badge_text="CLI Missing",
            output_text="`outguess` is not installed on system PATH.",
            command_run=masked_cmd,
        )

    out_file = os.path.join(workspace_dir, "outguess_extracted.dat")
    cmd = [outguess_bin]
    if password:
        cmd.extend(["-k", password])
    cmd.extend(["-r", abs_path, out_file])

    try:
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=20,
        )
        combined = (proc.stdout + "\n" + proc.stderr).strip()
        artifacts = []
        status = "clean"
        badge = "Done"
        if os.path.isfile(out_file) and os.path.getsize(out_file) > 0:
            with open(out_file, "rb") as f:
                raw_out = f.read(MAX_SINGLE_CARVE_BYTES)
            sample = raw_out[:256]
            printable_ratio = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13)) / max(1, len(sample))
            if printable_ratio > 0.65 or any(raw_out.startswith(s[1]) for s in MAGIC_SIGNATURES):
                status = "hit"
                badge = "Payload Found!"
                artifacts.append(
                    ExtractedArtifact(
                        name="outguess_extracted.dat",
                        path=out_file,
                        size=len(raw_out),
                        source_tool="OutGuess",
                        description="Extracted via OutGuess",
                    )
                )
                combined += f"\n\n[+] Preview:\n{raw_out[:300].decode('utf-8', errors='replace')}"
        return AnalyzerResult(
            tool_id="outguess",
            title="OutGuess JPEG Extractor",
            status=status,
            badge_text=badge,
            output_text=combined,
            command_run=masked_cmd,
            artifacts=artifacts,
        )
    except Exception as exc:
        return AnalyzerResult(
            tool_id="outguess",
            title="OutGuess JPEG Extractor",
            status="error",
            badge_text="Error",
            output_text=str(exc),
            command_run=masked_cmd,
        )
