"""Generate PWA / home-screen icons (requires Pillow)."""

from PIL import Image, ImageDraw

# Lightning-bolt outline in unit coordinates
BOLT = [
    (0.60, 0.10),
    (0.28, 0.57),
    (0.47, 0.57),
    (0.40, 0.90),
    (0.72, 0.43),
    (0.53, 0.43),
]


def make(size: int, path: str, *, rounded: bool = True) -> None:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    radius = size // 6 if rounded else 0

    # Background
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=(5, 7, 10, 255))
    # Cyan border
    bw = max(2, size // 110)
    d.rounded_rectangle(
        [bw, bw, size - 1 - bw, size - 1 - bw],
        radius=max(1, radius - bw),
        outline=(0, 229, 255, 170),
        width=bw,
    )
    # Lightning bolt
    poly = [(x * size, y * size) for x, y in BOLT]
    d.polygon(poly, fill=(0, 229, 255, 255))
    d.polygon(poly, outline=(170, 250, 255, 255))

    img.save(path)
    print(f"wrote {path} ({size}x{size})")


if __name__ == "__main__":
    make(512, "static/icon-512.png")
    make(192, "static/icon-192.png")
    make(180, "static/icon-180.png")
    make(64, "static/icon-64.png")
    make(512, "static/icon-maskable-512.png", rounded=False)
