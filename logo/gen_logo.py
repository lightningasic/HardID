#!/usr/bin/env python3
"""Regenerate logo.h from logo-hardid-1024.png.

DeepSeek v4 wrote the original logo.h without reading the PNG (no image
support), so the RGB565 values did not match the artwork. This generator
is the reproducible path: composite the RGBA artwork over the boot
screen's black background, downscale to the splash size, pack RGB565.

Usage: python3 logo/gen_logo.py
"""
import os
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "logo-hardid-1024.png")
DST = os.path.join(HERE, "..", "core", "logo.h")  # where the firmware includes it from
W = H = 160


def to_rgb565(px):
    r, g, b = px
    return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)


def main():
    im = Image.open(SRC).convert("RGBA")
    bg = Image.new("RGBA", im.size, (0, 0, 0, 255))   # boot screen is black
    im = Image.alpha_composite(bg, im).convert("RGB")
    im = im.resize((W, H), Image.LANCZOS)

    vals = [to_rgb565(im.getpixel((x, y))) for y in range(H) for x in range(W)]

    with open(DST, "w") as f:
        f.write("/* Auto-generated from logo/logo-hardid-1024.png"
                " by logo/gen_logo.py. DO NOT EDIT. */\n")
        f.write("#ifndef HARDID_LOGO_H\n#define HARDID_LOGO_H\n")
        f.write("#include <stdint.h>\n")
        f.write(f"#define LOGO_W {W}\n#define LOGO_H {H}\n")
        f.write("static const uint16_t logo_rgb565[LOGO_W*LOGO_H] = {\n")
        for i in range(0, len(vals), 12):
            f.write(", ".join(f"0x{v:04x}" for v in vals[i:i + 12]) + ",\n")
        f.write("};\n\n#endif /* HARDID_LOGO_H */\n")
    print(f"wrote {DST}: {W}x{H} RGB565 from {os.path.basename(SRC)}")


if __name__ == "__main__":
    main()
