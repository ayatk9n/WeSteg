# WeSteg - LSB & AES-256-GCM Encoder/Decoder

import os
import re
import struct
import tempfile
import textwrap
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple
import numpy as np
from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC_PLAIN = b"WESTEG01"
MAGIC_ENC = b"WESTGENC"
MAX_LSB_PAYLOAD_BYTES = 100 * 1024 * 1024
LOSSLESS_EXTENSIONS = {".png", ".bmp", ".tiff", ".tif"}


@dataclass
class LSBCapacity:
    width: int
    height: int
    channels_count: int
    bits_per_channel: int
    total_bits: int
    total_bytes: int
    usable_bytes: int = 0


def _sanitize_filename(raw_name: str, default: str = "extracted_payload.bin") -> str:
    normalized = raw_name.replace("\\", "/")
    base = os.path.basename(normalized)
    cleaned = re.sub(r'[\x00-\x1f\x7f<>:"/\\|?*]+', "_", base).strip(" .")
    if not cleaned or cleaned in (".", ".."):
        return default
    return cleaned[:128]


def _overhead_for_mode(mode: str, filename: str = "secret.bin") -> int:
    fname_len = len(_sanitize_filename(filename).encode("utf-8")[:255])
    if mode == "raw_zsteg":
        return 4
    if mode == "aes_gcm":
        return 61 + fname_len
    return 17 + fname_len


def calculate_lsb_capacity(
    image_path: str,
    channels: Sequence[str],
    bits: Sequence[int],
    mode: str = "raw_zsteg",
    filename: str = "secret.bin",
) -> LSBCapacity:
    with Image.open(image_path) as img:
        width, height = img.size
    valid_channels = [c for c in channels if c in ("R", "G", "B", "A")]
    valid_bits = sorted({b for b in bits if isinstance(b, int) and 0 <= b <= 7})
    ch_count = len(valid_channels)
    b_count = len(valid_bits)
    total_bits = width * height * ch_count * b_count
    total_bytes = total_bits // 8
    overhead = _overhead_for_mode(mode, filename) if total_bytes > 0 else 0
    usable = max(0, total_bytes - overhead)
    return LSBCapacity(
        width=width,
        height=height,
        channels_count=ch_count,
        bits_per_channel=b_count,
        total_bits=total_bits,
        total_bytes=total_bytes,
        usable_bytes=usable,
    )


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode("utf-8"))


def pack_payload(
    payload_bytes: bytes,
    filename: str = "secret.bin",
    mode: str = "raw_zsteg",
    password: str = "",
) -> bytes:
    if mode == "raw_zsteg":
        return payload_bytes + b"\x00\x00\x00\x00"

    safe_fname = _sanitize_filename(filename)
    fname_bytes = safe_fname.encode("utf-8")[:255]
    inner_body = (
        struct.pack(">B", len(fname_bytes))
        + fname_bytes
        + struct.pack(">I", len(payload_bytes))
        + payload_bytes
    )

    if mode == "aes_gcm":
        if not password:
            raise ValueError("Password is required for AES-256-GCM encryption mode.")
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = _derive_key(password, salt)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, inner_body, MAGIC_ENC)
        return (
            MAGIC_ENC
            + salt
            + nonce
            + struct.pack(">I", len(ciphertext))
            + ciphertext
        )

    return MAGIC_PLAIN + struct.pack(">I", len(inner_body)) + inner_body


def _normalize_lossless_output_path(output_path: str) -> str:
    ext = os.path.splitext(output_path)[1].lower()
    if not ext:
        return output_path + ".png"
    if ext not in LOSSLESS_EXTENSIONS:
        raise ValueError(
            f"LSB steganography requires a lossless format (.png or .bmp), got '{ext}'. "
            "Lossy formats like JPEG destroy LSB bit planes."
        )
    return output_path


def _atomic_pil_save(img: Image.Image, output_path: str) -> None:
    abs_out = os.path.abspath(output_path)
    out_dir = os.path.dirname(abs_out) or "."
    ext = os.path.splitext(abs_out)[1] or ".png"
    fd, tmp_path = tempfile.mkstemp(prefix=".westeg_tmp_", suffix=ext, dir=out_dir)
    os.close(fd)
    try:
        img.save(tmp_path)
        os.replace(tmp_path, abs_out)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def embed_lsb_data(
    cover_image_path: str,
    output_path: str,
    payload_bytes: bytes,
    channels: Sequence[str] = ("R", "G", "B"),
    bits: Sequence[int] = (0,),
    mode: str = "raw_zsteg",
    password: str = "",
    filename: str = "secret.txt",
) -> Tuple[int, LSBCapacity]:
    output_path = _normalize_lossless_output_path(output_path)
    channel_map = {"R": 0, "G": 1, "B": 2, "A": 3}
    selected_indices = [channel_map[c] for c in channels if c in channel_map]
    sorted_bits = sorted({b for b in bits if isinstance(b, int) and 0 <= b <= 7})

    if not selected_indices or not sorted_bits:
        raise ValueError("Select at least one valid color channel (R/G/B/A) and one bit plane (0-7).")

    with Image.open(cover_image_path) as raw_img:
        orig_mode = raw_img.mode
        rgba_img = raw_img.convert("RGBA")
        arr = np.array(rgba_img, dtype=np.uint8)

    height, width, _ = arr.shape

    stream_bytes = pack_payload(payload_bytes, filename=filename, mode=mode, password=password)
    payload_bits = np.unpackbits(np.frombuffer(stream_bytes, dtype=np.uint8))

    total_slots = height * width * len(selected_indices) * len(sorted_bits)
    if len(payload_bits) > total_slots:
        overhead = _overhead_for_mode(mode, filename)
        usable = max(0, (total_slots // 8) - overhead)
        raise ValueError(
            f"Payload size ({len(payload_bytes):,} bytes; {len(stream_bytes):,} bytes with framing) "
            f"exceeds selected LSB capacity ({usable:,} usable bytes)."
        )

    flat_pixels = arr.reshape(-1, 4)
    bit_cursor = 0
    total_payload_bits = len(payload_bits)

    for b in sorted_bits:
        if bit_cursor >= total_payload_bits:
            break
        mask = np.uint8(~(1 << b) & 0xFF)
        target_slice = flat_pixels[:, selected_indices].reshape(-1)
        remaining = total_payload_bits - bit_cursor
        chunk_len = min(len(target_slice), remaining)

        bits_chunk = payload_bits[bit_cursor : bit_cursor + chunk_len].astype(np.uint8)
        target_slice[:chunk_len] = (target_slice[:chunk_len] & mask) | (bits_chunk << b)

        flat_pixels[:, selected_indices] = target_slice.reshape(-1, len(selected_indices))
        bit_cursor += chunk_len

    modified_arr = flat_pixels.reshape(height, width, 4)
    out_img = Image.fromarray(modified_arr, mode="RGBA")
    if "A" not in channels and orig_mode == "RGB":
        out_img = out_img.convert("RGB")

    _atomic_pil_save(out_img, output_path)

    total_bytes = total_slots // 8
    usable_bytes = max(0, total_bytes - _overhead_for_mode(mode, filename))
    cap = LSBCapacity(
        width=width,
        height=height,
        channels_count=len(selected_indices),
        bits_per_channel=len(sorted_bits),
        total_bits=total_slots,
        total_bytes=total_bytes,
        usable_bytes=usable_bytes,
    )
    return len(stream_bytes), cap


def _extract_lsb_prefix_bytes(
    flat_pixels: np.ndarray,
    selected_indices: List[int],
    sorted_bits: List[int],
    num_bytes: int,
) -> bytes:
    bits_needed = num_bytes * 8
    if bits_needed <= 0:
        return b""

    samples_per_plane = flat_pixels.shape[0] * len(selected_indices)
    collected = []
    bits_collected = 0

    for b in sorted_bits:
        if bits_collected >= bits_needed:
            break
        need_from_plane = min(samples_per_plane, bits_needed - bits_collected)
        ch_count = len(selected_indices)
        pixels_needed = (need_from_plane + ch_count - 1) // ch_count
        sub_slice = flat_pixels[:pixels_needed, selected_indices].reshape(-1)[:need_from_plane]
        plane_bits = (sub_slice >> b) & 1
        collected.append(plane_bits)
        bits_collected += len(plane_bits)

    if not collected:
        return b""
    all_bits = np.concatenate(collected)
    usable_bit_len = (len(all_bits) // 8) * 8
    if usable_bit_len == 0:
        return b""
    return np.packbits(all_bits[:usable_bit_len]).tobytes()


def _parse_inner_framed_body(inner: bytes) -> Optional[Tuple[str, bytes]]:
    if len(inner) < 5:
        return None
    fname_len = inner[0]
    if 1 + fname_len + 4 > len(inner):
        return None
    raw_fname = inner[1 : 1 + fname_len].decode("utf-8", errors="replace")
    safe_fname = _sanitize_filename(raw_fname)
    data_len = struct.unpack(">I", inner[1 + fname_len : 5 + fname_len])[0]
    end_pos = 5 + fname_len + data_len
    if end_pos > len(inner):
        return None
    return safe_fname, inner[5 + fname_len : end_pos]


def extract_lsb_data(
    image_path: str,
    channels: Sequence[str] = ("R", "G", "B"),
    bits: Sequence[int] = (0,),
    password: str = "",
    max_raw_bytes: int = 8192,
    rgba_arr: Optional[np.ndarray] = None,
) -> Tuple[str, bytes, str]:
    channel_map = {"R": 0, "G": 1, "B": 2, "A": 3}
    selected_indices = [channel_map[c] for c in channels if c in channel_map]
    sorted_bits = sorted({b for b in bits if isinstance(b, int) and 0 <= b <= 7})

    if not selected_indices or not sorted_bits:
        raise ValueError("Select at least one valid color channel and bit plane.")

    if rgba_arr is None:
        with Image.open(image_path) as raw_img:
            arr = np.array(raw_img.convert("RGBA"), dtype=np.uint8)
    else:
        arr = rgba_arr

    flat_pixels = arr.reshape(-1, 4)
    total_avail_bytes = (flat_pixels.shape[0] * len(selected_indices) * len(sorted_bits)) // 8
    if total_avail_bytes == 0:
        return ("Raw LSB Bitstream Dump", b"", "lsb_extracted.bin")

    initial_window = min(total_avail_bytes, max(64, max_raw_bytes))
    head_bytes = _extract_lsb_prefix_bytes(flat_pixels, selected_indices, sorted_bits, initial_window)

    if len(head_bytes) >= 12 and head_bytes.startswith(MAGIC_PLAIN):
        inner_len = struct.unpack(">I", head_bytes[8:12])[0]
        if 5 <= inner_len <= min(MAX_LSB_PAYLOAD_BYTES, total_avail_bytes - 12):
            full_needed = 12 + inner_len
            full_bytes = (
                head_bytes[:full_needed]
                if len(head_bytes) >= full_needed
                else _extract_lsb_prefix_bytes(flat_pixels, selected_indices, sorted_bits, full_needed)
            )
            parsed = _parse_inner_framed_body(full_bytes[12 : 12 + inner_len])
            if parsed is not None:
                safe_fname, payload = parsed
                return ("WeSteg Framed Payload Extracted", payload, safe_fname)

    if len(head_bytes) >= 40 and head_bytes.startswith(MAGIC_ENC):
        ct_len = struct.unpack(">I", head_bytes[36:40])[0]
        if 21 <= ct_len <= min(MAX_LSB_PAYLOAD_BYTES, total_avail_bytes - 40):
            if not password:
                raise ValueError("Encrypted WeSteg LSB payload detected! Please enter the passphrase.")
            full_needed = 40 + ct_len
            full_bytes = (
                head_bytes[:full_needed]
                if len(head_bytes) >= full_needed
                else _extract_lsb_prefix_bytes(flat_pixels, selected_indices, sorted_bits, full_needed)
            )
            salt = full_bytes[8:24]
            nonce = full_bytes[24:36]
            ciphertext = full_bytes[40 : 40 + ct_len]
            key = _derive_key(password, salt)
            aesgcm = AESGCM(key)
            try:
                inner = aesgcm.decrypt(nonce, ciphertext, MAGIC_ENC)
            except Exception as exc:
                raise ValueError("Invalid passphrase or corrupted AES-256-GCM LSB payload.") from exc

            parsed = _parse_inner_framed_body(inner)
            if parsed is None:
                raise ValueError("Corrupted inner frame after AES-256-GCM decryption.")
            safe_fname, payload = parsed
            return ("AES-256-GCM Decrypted Payload Extracted", payload, safe_fname)

    raw_window = head_bytes[:max_raw_bytes]
    null_pos = raw_window.find(b"\x00\x00\x00\x00")
    trimmed = raw_window[:null_pos] if 0 < null_pos < max_raw_bytes else raw_window

    return ("Raw LSB Bitstream Dump", trimmed, "lsb_extracted.bin")


def _load_stamp_font(font_size: int):
    font_candidates = [
        "DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
        "arialbd.ttf",
        "arial.ttf",
    ]
    for candidate in font_candidates:
        try:
            return ImageFont.truetype(candidate, font_size)
        except Exception:
            continue
    try:
        return ImageFont.load_default(size=font_size)
    except TypeError:
        return ImageFont.load_default()


def stamp_visual_text_on_bitplane(
    cover_image_path: str,
    output_path: str,
    secret_text: str,
    channel: str = "R",
    bit: int = 0,
) -> None:
    output_path = _normalize_lossless_output_path(output_path)
    channel_map = {"R": 0, "G": 1, "B": 2, "A": 3}
    if channel not in channel_map:
        raise ValueError(f"Invalid channel '{channel}'. Expected R, G, B, or A.")
    if not (0 <= bit <= 7):
        raise ValueError(f"Invalid bit plane '{bit}'. Expected 0..7.")

    ch_idx = channel_map[channel]

    with Image.open(cover_image_path) as raw_img:
        orig_mode = raw_img.mode
        rgba_img = raw_img.convert("RGBA")
        width, height = rgba_img.size
        arr = np.array(rgba_img, dtype=np.uint8)

    mask_img = Image.new("L", (width, height), 0)
    draw = ImageDraw.Draw(mask_img)

    font_size = max(14, min(width, height) // 11)
    font = _load_stamp_font(font_size)

    margin = max(8, width // 25)
    approx_chars_per_line = max(8, int((width - 2 * margin) / max(1, font_size * 0.6)))
    wrapped_lines = []
    for raw_line in secret_text.splitlines() or [secret_text]:
        wrapped_lines.extend(textwrap.wrap(raw_line, width=approx_chars_per_line) or [""])
    wrapped_text = "\n".join(wrapped_lines[:12])

    y_pos = max(margin, height // 5)
    draw.multiline_text((margin, y_pos), wrapped_text, fill=1, font=font, spacing=6)

    mask_arr = (np.array(mask_img, dtype=np.uint8) > 0).astype(np.uint8)
    clear_mask = np.uint8(~(1 << bit) & 0xFF)
    arr[:, :, ch_idx] = (arr[:, :, ch_idx] & clear_mask) | (mask_arr << bit)

    out_img = Image.fromarray(arr, mode="RGBA")
    if channel != "A" and orig_mode == "RGB":
        out_img = out_img.convert("RGB")

    _atomic_pil_save(out_img, output_path)
