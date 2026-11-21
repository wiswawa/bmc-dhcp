#!/usr/bin/env python3
"""生成 App 图标：深色圆角底 + 蓝色网线 + 白色插头 + 绿色状态点。

    python3 tools/make_icon.py out/AppIcon.iconset && iconutil -c icns ...
"""

from __future__ import annotations

import os
import sys

from PIL import Image, ImageDraw

SIZE = 1024
SIZES = [16, 32, 64, 128, 256, 512, 1024]


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(len(a)))


def gradient(size):
    top = (26, 36, 48)
    bottom = (8, 11, 14)
    img = Image.new("RGB", (size, size))
    draw = ImageDraw.Draw(img)
    for y in range(size):
        draw.line([(0, y), (size, y)], fill=lerp(top, bottom, y / max(1, size - 1)))
    return img


def rounded_mask(size, radius):
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return mask


def build():
    img = gradient(SIZE).convert("RGBA")

    d = ImageDraw.Draw(img)

    # 右侧插头（白色圆角块）
    body = [372, 432, 700, 592]
    d.rounded_rectangle(body, radius=72, fill=(232, 238, 244, 255))

    # 插头引脚（深色小方块）
    for i in range(4):
        x = 566 + i * 32
        d.rounded_rectangle([x, 470, x + 16, 554], radius=8, fill=(16, 22, 28, 255))

    # 网线（蓝色粗线 + 圆头）
    d.rounded_rectangle([120, 492, 400, 532], radius=20, fill=(62, 166, 255, 255))
    d.ellipse([96, 468, 176, 556], fill=(62, 166, 255, 255))

    # 绿色状态灯
    d.ellipse([760, 452, 900, 592], fill=(63, 185, 80, 255))
    d.ellipse([786, 478, 874, 566], fill=(120, 228, 140, 255))

    # 顶部一点点高光
    sheen = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    ImageDraw.Draw(sheen).ellipse([-260, -620, 1280, 460], fill=(255, 255, 255, 16))
    img = Image.alpha_composite(img, sheen)

    out = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    out.paste(img, (0, 0), rounded_mask(SIZE, 224))
    return out


def main(argv):
    target = argv[1] if len(argv) > 1 else "build/AppIcon.iconset"
    os.makedirs(target, exist_ok=True)
    master = build()
    master.save(os.path.join(os.path.dirname(target) or ".", "AppIcon-1024.png"))

    mapping = {
        16: ["icon_16x16.png"],
        32: ["icon_16x16@2x.png", "icon_32x32.png"],
        64: ["icon_32x32@2x.png"],
        128: ["icon_128x128.png"],
        256: ["icon_128x128@2x.png", "icon_256x256.png"],
        512: ["icon_256x256@2x.png", "icon_512x512.png"],
        1024: ["icon_512x512@2x.png"],
    }
    for size, names in mapping.items():
        resized = master.resize((size, size), Image.LANCZOS)
        for name in names:
            resized.save(os.path.join(target, name))
    print("iconset ->", target)


if __name__ == "__main__":
    main(sys.argv)
