#!/usr/bin/env python3
"""
Convert a PNG image to a Windows .ico file for BitWitness.
Usage:  python convert_icon.py <input.png>
Output: bitwitness.ico in the same directory as this script.
"""

import sys
import os

try:
    from PIL import Image
except ImportError:
    print("[ERROR] Pillow not installed. Run: pip install Pillow")
    sys.exit(1)


def convert_to_ico(png_path: str, ico_path: str):
    """Convert a PNG to a multi-size .ico file."""
    img = Image.open(png_path).convert("RGBA")
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(ico_path, format="ICO", sizes=sizes)
    print(f"[OK] Icon saved: {ico_path}")
    print(f"     Sizes: {', '.join(f'{w}x{h}' for w, h in sizes)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python convert_icon.py <input.png>")
        print("  This will create bitwitness.ico in the project directory.")
        sys.exit(1)

    png_file = sys.argv[1]
    if not os.path.isfile(png_file):
        print(f"[ERROR] File not found: {png_file}")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output = os.path.join(script_dir, "bitwitness.ico")
    convert_to_ico(png_file, output)
