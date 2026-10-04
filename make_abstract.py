"""Render the graphical abstract for NMAP SCANNER.

Creates docs/graphical-abstract.png — a single-panel visual summary of the
project (flow: interfaces -> security gate -> nmap engine -> results).

Run:  python make_abstract.py
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 720

BG = (7, 11, 18)
GRID = (13, 20, 32)
GREEN = (0, 255, 156)
CYAN = (0, 229, 255)
PURPLE = (150, 140, 255)
ORANGE = (255, 171, 0)
PINK = (255, 95, 135)
WHITE = (235, 242, 250)
GRAY = (132, 148, 170)
DIM = (0, 150, 105)
BOX_FILL = (11, 18, 31)

FDIR = Path("C:/Windows/Fonts")


def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FDIR / name), size)


F_TITLE = font("segoeuib.ttf", 60)
F_SUB = font("segoeui.ttf", 23)
F_BOX = font("segoeuib.ttf", 25)
F_ITEM = font("segoeui.ttf", 18)
F_CHIP = font("segoeuib.ttf", 17)
F_NOTE = font("segoeui.ttf", 18)


def box(d: ImageDraw.ImageDraw, xy, title: str, items, accent, align="left"):
    x0, y0, x1, y1 = xy
    d.rounded_rectangle(xy, radius=14, fill=BOX_FILL, outline=accent, width=2)
    # accent tab
    d.rounded_rectangle((x0, y0, x1, y0 + 7), radius=4, fill=accent)
    cx = (x0 + x1) // 2
    if align == "center":
        d.text((cx, y0 + 42), title, font=F_BOX, fill=accent, anchor="mm")
        y = y0 + 82
        for it in items:
            d.text((cx, y), it, font=F_ITEM, fill=WHITE, anchor="mm")
            y += 30
    else:
        d.text((x0 + 20, y0 + 40), title, font=F_BOX, fill=accent, anchor="lm")
        y = y0 + 78
        for it in items:
            d.text((x0 + 20, y), "\u2022 " + it, font=F_ITEM, fill=WHITE, anchor="lm")
            y += 31


def arrow(d: ImageDraw.ImageDraw, x0, y0, x1, y1, color=DIM, width=4, head=13):
    d.line((x0, y0, x1, y1), fill=color, width=width)
    if x1 >= x0:  # pointing right
        d.polygon([(x1, y1), (x1 - head, y1 - head // 2 - 2),
                   (x1 - head, y1 + head // 2 + 2)], fill=color)
    else:  # pointing left
        d.polygon([(x1, y1), (x1 + head, y1 - head // 2 - 2),
                   (x1 + head, y1 + head // 2 + 2)], fill=color)


def chip(d: ImageDraw.ImageDraw, x, y, text, color):
    pad = 16
    w = d.textlength(text, font=F_CHIP) + pad * 2
    d.rounded_rectangle((x, y, x + w, y + 34), radius=17,
                        fill=(10, 16, 27), outline=color, width=2)
    d.text((x + w / 2, y + 17), text, font=F_CHIP, fill=color, anchor="mm")
    return w


def main() -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # subtle grid
    for x in range(0, W, 40):
        d.line((x, 0, x, H), fill=GRID, width=1)
    for y in range(0, H, 40):
        d.line((0, y, W, y), fill=GRID, width=1)

    # header
    d.text((W // 2, 62), "NMAP SCANNER", font=F_TITLE, fill=GREEN, anchor="mm")
    d.text((W // 2, 112),
           "Telegram bot + web dashboard \u00b7 scan any IP for ports & services",
           font=F_SUB, fill=GRAY, anchor="mm")
    d.line((40, 146, W - 40, 146), fill=GREEN, width=2)

    # left: interfaces
    box(d, (40, 170, 320, 330), "TELEGRAM BOT",
        ["/scan \u00b7 /fullscan", "/status \u00b7 instant reply",
         ".txt file if output > 4096"], CYAN)
    box(d, (40, 360, 320, 520), "WEB DASHBOARD",
        ["real-time cyber UI", "PWA \u00b7 Android / iOS", "dark lock screen"], PURPLE)

    # bus connector -> gate
    d.line((320, 250, 350, 250), fill=DIM, width=4)
    d.line((320, 440, 350, 440), fill=DIM, width=4)
    d.line((350, 250, 350, 440), fill=DIM, width=4)
    arrow(d, 350, 345, 380, 345)

    # gate / engine / results
    box(d, (380, 230, 640, 460), "SECURITY GATE",
        ["CAPTCHA image", "access code", "rate limit: 1 + 30s",
         "session cookie (30d)"], ORANGE)
    arrow(d, 640, 345, 700, 345)
    box(d, (700, 230, 960, 460), "NMAP ENGINE",
        ["fixed scan profiles", "top-1000 \u00b7 -sV \u00b7 -T4",
         "300s timeout + kill", "2 scans max, no shell"], GREEN)
    arrow(d, 960, 345, 1020, 345)
    box(d, (1020, 230, 1240, 460), "RESULTS",
        ["open ports", "services & versions", "live in chat / UI",
         "logged to scan_logs"], PINK)

    # return note
    d.text((W // 2, 495),
           "results stream back to Telegram & web in real time",
           font=F_NOTE, fill=GRAY, anchor="mm")

    # tech chips
    chips = ["Python 3.10", "python-telegram-bot", "FastAPI", "nmap",
             "Docker", "Cloudflare tunnel"]
    widths = [d.textlength(t, font=F_CHIP) + 32 for t in chips]
    total = sum(widths) + 16 * (len(chips) - 1)
    x = (W - total) / 2
    colors = [CYAN, CYAN, PURPLE, GREEN, ORANGE, PINK]
    for t, w, c in zip(chips, widths, colors):
        x += chip(d, x, 545, t, c) + 16

    # footer
    d.text((W // 2, 632),
           "IPv4 / IPv6 only \u2014 hostnames & CIDR rejected \u00b7 "
           "fixed profiles \u00b7 no shell=True \u00b7 graceful errors",
           font=F_NOTE, fill=(95, 110, 130), anchor="mm")
    d.text((W // 2, 672),
           "github.com/Aryan-mortazavi/NMAP-SCANNER",
           font=F_NOTE, fill=DIM, anchor="mm")

    out = Path(__file__).parent / "docs" / "graphical-abstract.png"
    out.parent.mkdir(exist_ok=True)
    img.save(out, optimize=True)
    print(f"saved {out} ({out.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
