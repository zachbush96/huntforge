"""Build a reproducible, lossless web-asset optimization from trusted sources."""

from pathlib import Path

from PIL import Image, ImageChops

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "website/assets/halftone.png"
OPTIMIZED = ROOT / "website/assets/halftone.webp"
STYLE = ROOT / "website/style.css"


def main():
    if not SOURCE.exists():
        if not OPTIMIZED.exists() or "assets/halftone.webp" not in STYLE.read_text(encoding="utf-8"):
            raise ValueError("The optimized asset or stylesheet reference is missing")
        print("No eligible asset optimization found")
        return
    with Image.open(SOURCE) as original:
        if original.width * original.height > 8_000_000:
            raise ValueError("The trusted decorative asset exceeds its pixel budget")
        original = original.convert("RGB")
        original.save(OPTIMIZED, lossless=True, method=6)
        with Image.open(OPTIMIZED) as optimized:
            if ImageChops.difference(original, optimized.convert("RGB")).getbbox():
                raise ValueError("The optimized asset does not preserve the original pixels")
    if OPTIMIZED.stat().st_size >= SOURCE.stat().st_size:
        OPTIMIZED.unlink()
        print("The candidate did not reduce the asset size")
        return
    css = STYLE.read_text(encoding="utf-8")
    if "assets/halftone.png" not in css:
        raise ValueError("The trusted source reference has changed")
    STYLE.write_bytes(css.replace("assets/halftone.png", "assets/halftone.webp").encode())
    size_reduction = SOURCE.stat().st_size - OPTIMIZED.stat().st_size
    SOURCE.unlink()
    print(f"Verified a pixel-identical asset and saved {size_reduction:,} bytes")


if __name__ == "__main__":
    main()
