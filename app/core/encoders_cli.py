# WeSteg - External CLI Steganography Wrappers

import os
import re
import shutil
import subprocess
import tempfile
from typing import Tuple


def _safe_payload_basename(name: str) -> str:
    base = os.path.basename(name.replace("\\", "/"))
    clean = re.sub(r'[\x00-\x1f\x7f<>:"/\\|?*]+', "_", base).strip(" .")
    return clean[:120] or "secret.bin"


def embed_with_steghide(
    cover_file_path: str,
    output_file_path: str,
    payload_bytes: bytes,
    payload_filename: str = "secret.txt",
    passphrase: str = "",
    compression_level: int = 9,
) -> Tuple[bool, str]:
    steghide_bin = shutil.which("steghide")
    if not steghide_bin:
        return (
            False,
            "Steghide binary not found on system PATH. Install `steghide` on your system PATH to use this wrapper.",
        )

    abs_cover = os.path.abspath(cover_file_path)
    abs_out = os.path.abspath(output_file_path)
    ext = os.path.splitext(abs_cover)[1].lower()
    if ext not in (".jpg", ".jpeg", ".bmp", ".wav", ".au"):
        return (
            False,
            f"Steghide only supports JPEG, BMP, WAV, and AU cover files (got '{ext}'). "
            "For PNG files, use the LSB Encoder (with AES-256-GCM) or OpenStego.",
        )

    comp = max(1, min(9, int(compression_level)))

    with tempfile.TemporaryDirectory(prefix="westeg_steghide_") as tmpdir:
        secret_path = os.path.join(tmpdir, _safe_payload_basename(payload_filename))
        with open(secret_path, "wb") as f:
            f.write(payload_bytes)

        staged_out = os.path.join(tmpdir, f"staged_stego{ext}")
        cmd = [
            steghide_bin,
            "embed",
            "-cf",
            abs_cover,
            "-ef",
            secret_path,
            "-sf",
            staged_out,
            "-p",
            passphrase,
            "-z",
            str(comp),
            "-f",
        ]
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output_msg = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode == 0 and os.path.exists(staged_out) and os.path.getsize(staged_out) > 0:
            shutil.copy2(staged_out, abs_out)
            return (True, output_msg or f"Successfully embedded {len(payload_bytes):,} bytes with Steghide.")
        return (False, output_msg or "Steghide embedding failed.")


def embed_with_outguess(
    cover_file_path: str,
    output_file_path: str,
    payload_bytes: bytes,
    passphrase: str = "",
) -> Tuple[bool, str]:
    outguess_bin = shutil.which("outguess")
    if not outguess_bin:
        return (
            False,
            "OutGuess binary not found on system PATH. Install `outguess` on your system PATH to use this wrapper.",
        )

    abs_cover = os.path.abspath(cover_file_path)
    abs_out = os.path.abspath(output_file_path)
    ext = os.path.splitext(abs_cover)[1].lower()
    if ext not in (".jpg", ".jpeg", ".ppm", ".pnm"):
        return (
            False,
            f"OutGuess requires a JPEG, PPM, or PNM cover image (got '{ext}').",
        )

    with tempfile.TemporaryDirectory(prefix="westeg_outguess_") as tmpdir:
        secret_path = os.path.join(tmpdir, "secret.dat")
        with open(secret_path, "wb") as f:
            f.write(payload_bytes)

        staged_out = os.path.join(tmpdir, f"staged_outguess{ext}")
        cmd = [outguess_bin]
        if passphrase:
            cmd.extend(["-k", passphrase])
        cmd.extend(["-d", secret_path, abs_cover, staged_out])

        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output_msg = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode == 0 and os.path.exists(staged_out) and os.path.getsize(staged_out) > 0:
            shutil.copy2(staged_out, abs_out)
            return (True, output_msg or f"Successfully embedded {len(payload_bytes):,} bytes with OutGuess.")
        return (False, output_msg or "OutGuess embedding failed (payload may exceed JPEG DCT capacity).")


def embed_with_openstego(
    cover_file_path: str,
    output_file_path: str,
    payload_bytes: bytes,
    payload_filename: str = "secret.txt",
    passphrase: str = "",
) -> Tuple[bool, str]:
    openstego_bin = shutil.which("openstego")
    if not openstego_bin:
        return (
            False,
            "OpenStego binary not found on system PATH. Install `openstego` on your system PATH to use this wrapper.",
        )

    abs_cover = os.path.abspath(cover_file_path)
    abs_out = os.path.abspath(output_file_path)
    ext = os.path.splitext(abs_out)[1] or ".png"
    if not os.path.splitext(abs_out)[1]:
        abs_out += ".png"

    with tempfile.TemporaryDirectory(prefix="westeg_openstego_") as tmpdir:
        secret_path = os.path.join(tmpdir, _safe_payload_basename(payload_filename))
        with open(secret_path, "wb") as f:
            f.write(payload_bytes)

        staged_out = os.path.join(tmpdir, f"staged_openstego{ext}")
        cmd = [
            openstego_bin,
            "embed",
            "-mf",
            secret_path,
            "-cf",
            abs_cover,
            "-sf",
            staged_out,
        ]
        if passphrase:
            cmd.extend(["-e", "-p", passphrase])

        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=45,
        )
        output_msg = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode == 0 and os.path.exists(staged_out) and os.path.getsize(staged_out) > 0:
            shutil.copy2(staged_out, abs_out)
            return (True, output_msg or f"Successfully embedded {len(payload_bytes):,} bytes with OpenStego.")
        return (False, output_msg or "OpenStego embedding failed.")
