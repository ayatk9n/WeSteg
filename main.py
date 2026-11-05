#!/usr/bin/env python3
# WeSteg - Application Entrypoint

import argparse
import os
import sys


def run_self_test() -> int:
    import tempfile
    import zipfile
    from PIL import Image
    from app.core.bitplanes import analyze_visual_layers, compute_image_xor_diff
    from app.core.encoders_lsb import (
        calculate_lsb_capacity,
        embed_lsb_data,
        extract_lsb_data,
        stamp_visual_text_on_bitplane,
    )
    from app.core.encoders_meta import (
        inject_exif_metadata,
        inject_png_chunk,
        parse_png_chunks,
        append_eof_payload,
        detect_eof_trailing_data,
    )
    from app.core.analyzers import (
        run_file_and_hashes,
        run_exiftool_analyzer,
        run_pngcheck_analyzer,
        run_zsteg_analyzer,
        run_binwalk_foremost_analyzer,
        run_strings_analyzer,
    )

    print("[*] Starting WeSteg End-to-End Self-Test...")
    with tempfile.TemporaryDirectory(prefix="westeg_test_") as tmp:
        cover_png = os.path.join(tmp, "cover.png")
        img = Image.new("RGBA", (240, 160), (45, 90, 160, 255))
        img.save(cover_png)

        planes, filters = analyze_visual_layers(cover_png)
        assert len(planes["Red"]) == 8 and len(planes["RGB"]) == 8, "Bit-plane count mismatch"
        assert len(filters) == 8, "Color transforms count mismatch"
        print("  [+] Visual Bit-Plane Decomposer (40 planes) & Color Remapper (8 filters): OK")

        cap = calculate_lsb_capacity(cover_png, ["R", "G", "B"], [0], mode="aes_gcm", filename="flag.txt")
        assert 0 < cap.usable_bytes < cap.total_bytes, "Usable capacity overhead calculation failed"

        stego_aes = os.path.join(tmp, "stego_aes.png")
        secret_msg = b"CTF{w3st3g_a3s_256_gcm_st3g0_w0rks!}"
        embed_lsb_data(
            cover_png,
            stego_aes,
            secret_msg,
            channels=["R", "G", "B"],
            bits=[0],
            mode="aes_gcm",
            password="test_secret_pass",
            filename="../../etc/passwd",
        )
        mode_desc, extracted_bytes, safe_fname = extract_lsb_data(
            stego_aes,
            channels=["R", "G", "B"],
            bits=[0],
            password="test_secret_pass",
        )
        assert extracted_bytes == secret_msg and safe_fname == "passwd", f"Sanitization/roundtrip failed: {safe_fname}"
        diff_img = compute_image_xor_diff(cover_png, stego_aes)
        assert diff_img.size == (240, 160)
        print("  [+] LSB Encoder & Decoder (Exact Capacity, AES-256-GCM, Path Sanitization, XOR Diff): OK")

        stamped_png = os.path.join(tmp, "stamped.png")
        img.save(stamped_png)
        stamp_visual_text_on_bitplane(stamped_png, stamped_png, "HIDDEN LAYER 0", channel="R", bit=0)
        assert os.path.exists(stamped_png) and os.path.getsize(stamped_png) > 0
        print("  [+] Visual Bit-Plane Text Stamper & Atomic In-Place Save: OK")

        chunk_png = os.path.join(tmp, "chunk.png")
        large_compressible = b"CTF{png_ztxt_chunk_payload}_" + (b"A" * 200_000)
        inject_png_chunk(cover_png, chunk_png, "zTXt", "SecretFlag", large_compressible)
        chunks, _ = parse_png_chunks(chunk_png)
        assert any(c.chunk_type == "zTXt" and "CTF{png_ztxt_chunk_payload}" in c.preview for c in chunks)
        print("  [+] PNG Custom Chunk Injector, CRC32 Verifier & Bounded zTXt Decompressor: OK")

        prog_jpg = os.path.join(tmp, "progressive.jpg")
        img.convert("RGB").save(prog_jpg, format="JPEG", progressive=True)
        assert detect_eof_trailing_data(prog_jpg) is None, "Clean progressive JPEG triggered false EOF hit"
        append_eof_payload(prog_jpg, prog_jpg, b"TRAILING_JPEG_SECRET")
        jpg_eof = detect_eof_trailing_data(prog_jpg)
        assert jpg_eof is not None and jpg_eof[2] == b"TRAILING_JPEG_SECRET", "Progressive JPEG EOF detection failed"
        print("  [+] Progressive / Multi-Scan JPEG EOI Trailing Data Detector: OK")

        zip_path = os.path.join(tmp, "hidden.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("inside_zip.txt", "Secret archive inside image EOF!")
        with open(zip_path, "rb") as zf_in:
            zip_bytes = zf_in.read()

        poly_png = os.path.join(tmp, "polyglot.png")
        append_eof_payload(chunk_png, poly_png, zip_bytes)
        eof_res = detect_eof_trailing_data(poly_png)
        assert eof_res is not None and eof_res[2] == zip_bytes

        work_dir = os.path.join(tmp, "work")
        os.makedirs(work_dir, exist_ok=True)
        r_info = run_file_and_hashes(poly_png)
        r_exif = run_exiftool_analyzer(poly_png)
        r_png = run_pngcheck_analyzer(poly_png, work_dir)
        r_zsteg = run_zsteg_analyzer(stego_aes, work_dir, password="test_secret_pass")
        r_binwalk = run_binwalk_foremost_analyzer(poly_png, work_dir)
        r_strings = run_strings_analyzer(poly_png)

        assert r_info.status == "info"
        assert r_exif.status in ("hit", "info", "clean")
        assert r_png.status == "hit" and len(r_png.artifacts) >= 1
        assert r_zsteg.status == "hit" and len(r_zsteg.artifacts) >= 1
        assert r_binwalk.status == "hit" and len(r_binwalk.artifacts) >= 1
        assert r_strings.status in ("hit", "info")
        print("  [+] Automated Analyzers & Validated Carver (File/Exif/pngcheck/zsteg/Binwalk/Strings): OK")

    print("[+] All WeSteg self-tests passed successfully!")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="WeSteg - Steganalysis and Steganography Suite (Windows & Linux)"
    )
    parser.add_argument("file", nargs="?", help="Optional image or file to open and analyze on startup")
    parser.add_argument("--self-test", action="store_true", help="Run headless verification tests and exit")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(run_self_test())

    from PyQt6.QtWidgets import QApplication
    from app.ui.main_window import WeStegMainWindow
    from app.ui.theme import apply_channel_palette

    app = QApplication(sys.argv)
    app.setApplicationName("WeSteg")
    apply_channel_palette(app)
    win = WeStegMainWindow(initial_file=args.file)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
