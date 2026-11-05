# WeSteg - CLI Tool Discovery

import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class ToolStatus:
    name: str
    binary: str
    installed: bool
    path: str
    version: str
    category: str
    description: str
    fallback_available: bool = False


TOOL_DEFINITIONS = [
    {
        "name": "ExifTool",
        "binaries": ["exiftool"],
        "version_args": ["-ver"],
        "category": "Metadata",
        "description": "Reads and writes EXIF, IPTC, XMP, and maker metadata.",
        "fallback": True,
    },
    {
        "name": "zsteg",
        "binaries": ["zsteg"],
        "version_args": ["--version"],
        "category": "LSB Analysis",
        "description": "Detects LSB steganography in PNG and BMP images.",
        "fallback": True,
    },
    {
        "name": "Steghide",
        "binaries": ["steghide"],
        "version_args": ["--version"],
        "category": "Password Stego",
        "description": "Embeds and extracts passphrase-protected payloads in JPEG/BMP/WAV/AU.",
        "fallback": False,
    },
    {
        "name": "Stegseek",
        "binaries": ["stegseek"],
        "version_args": ["--version"],
        "category": "Password Cracker",
        "description": "High-speed steghide cracker and unencrypted seed extractor.",
        "fallback": False,
    },
    {
        "name": "Binwalk",
        "binaries": ["binwalk", "binwalk3"],
        "version_args": ["--version"],
        "category": "File Carving",
        "description": "Scans for embedded file signatures and extracts appended archives.",
        "fallback": True,
    },
    {
        "name": "Foremost",
        "binaries": ["foremost"],
        "version_args": ["-V"],
        "category": "File Carving",
        "description": "Carves embedded files based on header and footer structures.",
        "fallback": True,
    },
    {
        "name": "pngcheck",
        "binaries": ["pngcheck"],
        "version_args": ["-v"],
        "category": "Structure Integrity",
        "description": "Verifies PNG chunk CRCs, structure, and detects trailing data.",
        "fallback": True,
    },
    {
        "name": "OutGuess",
        "binaries": ["outguess"],
        "version_args": [],
        "category": "JPEG DCT Stego",
        "description": "Inserts and extracts hidden data in redundant DCT bits of JPEG/PPM.",
        "fallback": False,
    },
    {
        "name": "OpenStego",
        "binaries": ["openstego"],
        "version_args": ["--version"],
        "category": "Stego & Watermarking",
        "description": "Data hiding and watermarking tool supporting password encryption.",
        "fallback": False,
    },
    {
        "name": "strings",
        "binaries": ["strings"],
        "version_args": ["--version"],
        "category": "Binary Analysis",
        "description": "Extracts printable ASCII/UTF-8 character sequences from files.",
        "fallback": True,
    },
    {
        "name": "file",
        "binaries": ["file"],
        "version_args": ["--version"],
        "category": "Binary Analysis",
        "description": "Determines true MIME type and file header format via libmagic.",
        "fallback": True,
    },
]


def _get_version(binary_path: str, args: List[str]) -> str:
    if not binary_path:
        return "Not installed"
    if not args:
        return "Installed"
    try:
        proc = subprocess.run(
            [binary_path] + args,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=3,
        )
        output = (proc.stdout or proc.stderr or "").strip()
        for line in output.splitlines():
            clean = line.strip()
            if clean:
                return clean[:65]
        return "Installed"
    except Exception:
        return "Installed"


def check_all_tools() -> List[ToolStatus]:
    results: List[ToolStatus] = []
    for item in TOOL_DEFINITIONS:
        resolved_bin = item["binaries"][0]
        path = ""
        for candidate in item["binaries"]:
            found = shutil.which(candidate)
            if found:
                resolved_bin = candidate
                path = found
                break

        installed = bool(path)
        if installed:
            version = _get_version(path, item["version_args"])
        elif item["fallback"]:
            version = "Missing (Native Python fallback active)"
        else:
            version = "Missing (Optional CLI binary not on PATH)"

        results.append(
            ToolStatus(
                name=item["name"],
                binary=resolved_bin,
                installed=installed,
                path=path,
                version=version,
                category=item["category"],
                description=item["description"],
                fallback_available=item["fallback"],
            )
        )
    return results


def get_tool_map() -> Dict[str, ToolStatus]:
    return {t.binary: t for t in check_all_tools()}
