# WeSteg - Bit-Plane & Color Filter Engine

from dataclasses import dataclass
from typing import Dict, List, Tuple
import numpy as np
from PIL import Image, ImageOps

MAX_FORENSIC_PIXELS = 25_000_000
Image.MAX_IMAGE_PIXELS = 50_000_000


@dataclass
class BitPlaneItem:
    channel: str
    bit: int
    label: str
    image: Image.Image


@dataclass
class FilterPlaneItem:
    name: str
    description: str
    image: Image.Image


def _load_checked_rgba(image_path: str) -> np.ndarray:
    with Image.open(image_path) as raw_img:
        w, h = raw_img.size
        if w * h > MAX_FORENSIC_PIXELS:
            raise ValueError(
                f"Image dimensions ({w}x{h} = {w * h:,} px) exceed safe bit-plane memory limit "
                f"({MAX_FORENSIC_PIXELS:,} px)."
            )
        rgba_img = raw_img.convert("RGBA")
        return np.array(rgba_img, dtype=np.uint8)


def _decompose_from_rgba_array(arr: np.ndarray) -> Dict[str, List[BitPlaneItem]]:
    channels_map = {
        "Red": 0,
        "Green": 1,
        "Blue": 2,
        "Alpha": 3,
    }

    results: Dict[str, List[BitPlaneItem]] = {
        "Red": [],
        "Green": [],
        "Blue": [],
        "Alpha": [],
        "RGB": [],
    }

    for ch_name, ch_idx in channels_map.items():
        ch_data = arr[:, :, ch_idx]
        for bit in range(8):
            plane = ((ch_data >> bit) & 1) * np.uint8(255)
            plane_img = Image.fromarray(plane, mode="L")
            results[ch_name].append(
                BitPlaneItem(
                    channel=ch_name,
                    bit=bit,
                    label=f"{ch_name} - Bit {bit}" + (" (LSB)" if bit == 0 else " (MSB)" if bit == 7 else ""),
                    image=plane_img,
                )
            )

    rgb_data = arr[:, :, :3]
    for bit in range(8):
        rgb_plane = ((rgb_data >> bit) & 1) * np.uint8(255)
        rgb_img = Image.fromarray(rgb_plane, mode="RGB")
        results["RGB"].append(
            BitPlaneItem(
                channel="RGB",
                bit=bit,
                label=f"RGB Combined - Bit {bit}" + (" (LSB)" if bit == 0 else " (MSB)" if bit == 7 else ""),
                image=rgb_img,
            )
        )

    return results


def _transforms_from_rgb_array(rgb_arr: np.ndarray) -> List[FilterPlaneItem]:
    pil_rgb = Image.fromarray(rgb_arr, mode="RGB")
    transforms: List[FilterPlaneItem] = []

    inv_img = ImageOps.invert(pil_rgb)
    transforms.append(
        FilterPlaneItem(
            name="Inverted (Negative)",
            description="Inverts all RGB pixel intensities (255 - value)",
            image=inv_img,
        )
    )

    eq_img = ImageOps.equalize(pil_rgb)
    transforms.append(
        FilterPlaneItem(
            name="Histogram Equalized",
            description="Non-linear contrast stretch to expose subtle pixel variations",
            image=eq_img,
        )
    )

    lsb2 = (rgb_arr & 0x03) * np.uint8(85)
    transforms.append(
        FilterPlaneItem(
            name="Amplified Lower 2 Bits",
            description="Scales bits 0 and 1 across full 0-255 dynamic range",
            image=Image.fromarray(lsb2, mode="RGB"),
        )
    )

    xor_rg = np.bitwise_xor(rgb_arr[:, :, 0], rgb_arr[:, :, 1])
    xor_gb = np.bitwise_xor(rgb_arr[:, :, 1], rgb_arr[:, :, 2])
    xor_rb = np.bitwise_xor(rgb_arr[:, :, 0], rgb_arr[:, :, 2])
    xor_stack = np.stack([xor_rg, xor_gb, xor_rb], axis=-1)
    transforms.append(
        FilterPlaneItem(
            name="Inter-Channel XOR Anomaly",
            description="Highlights disparities between R/G/B channels (R^G, G^B, R^B)",
            image=Image.fromarray(xor_stack, mode="RGB"),
        )
    )

    seeds = [42, 1337, 7331, 9001]
    for idx, seed in enumerate(seeds, start=1):
        rng = np.random.default_rng(seed)
        lut_r = rng.permutation(256).astype(np.uint8)
        lut_g = rng.permutation(256).astype(np.uint8)
        lut_b = rng.permutation(256).astype(np.uint8)

        remapped = np.stack(
            [
                lut_r[rgb_arr[:, :, 0]],
                lut_g[rgb_arr[:, :, 1]],
                lut_b[rgb_arr[:, :, 2]],
            ],
            axis=-1,
        )
        transforms.append(
            FilterPlaneItem(
                name=f"Random Palette Map #{idx}",
                description=f"Pseudo-random color LUT permutation (Seed {seed}) to reveal hidden color indices",
                image=Image.fromarray(remapped, mode="RGB"),
            )
        )

    return transforms


def decompose_bit_planes(image_path: str) -> Dict[str, List[BitPlaneItem]]:
    arr = _load_checked_rgba(image_path)
    return _decompose_from_rgba_array(arr)


def generate_color_transforms(image_path: str) -> List[FilterPlaneItem]:
    arr = _load_checked_rgba(image_path)
    return _transforms_from_rgb_array(arr[:, :, :3])


def analyze_visual_layers(
    image_path: str,
) -> Tuple[Dict[str, List[BitPlaneItem]], List[FilterPlaneItem]]:
    arr = _load_checked_rgba(image_path)
    planes = _decompose_from_rgba_array(arr)
    transforms = _transforms_from_rgb_array(arr[:, :, :3])
    return planes, transforms


def compute_image_xor_diff(image_a_path: str, image_b_path: str) -> Image.Image:
    with Image.open(image_a_path) as raw_a:
        if raw_a.width * raw_a.height > MAX_FORENSIC_PIXELS:
            raise ValueError("Primary image exceeds safe pixel limit for XOR diff.")
        img_a = raw_a.convert("RGB")

    with Image.open(image_b_path) as raw_b:
        if raw_b.width * raw_b.height > MAX_FORENSIC_PIXELS:
            raise ValueError("Comparison image exceeds safe pixel limit for XOR diff.")
        img_b = raw_b.convert("RGB")

    if img_a.size != img_b.size:
        img_b = img_b.resize(img_a.size, Image.Resampling.NEAREST)

    arr_a = np.array(img_a, dtype=np.uint8)
    arr_b = np.array(img_b, dtype=np.uint8)
    diff = np.bitwise_xor(arr_a, arr_b).astype(np.uint16)
    amplified = np.where(diff > 0, np.clip(diff * 64 + 127, 0, 255), 0).astype(np.uint8)
    return Image.fromarray(amplified, mode="RGB")
