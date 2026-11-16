"""Dibujo de los códigos QR en PNG, SVG y PDF, con el mismo diseño en los tres formatos.

El diseño se calcula en "módulos" (los cuadraditos del QR) y luego se traduce a píxeles (PNG/PDF)
o a coordenadas SVG, para que todos los formatos se vean iguales.
"""
import base64
import io
import re
from functools import lru_cache
from html import escape

import segno
from PIL import Image, ImageDraw, ImageFont

HEX = re.compile(r"^#[0-9a-fA-F]{6}$")
DEFAULT_FG, DEFAULT_BG = "#000000", "#ffffff"
MARK_COLOR = "#6b6880"
FONT_PATHS = ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
              "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf")


def _lum(hex_color: str) -> float:
    def ch(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def check_colors(fg: str, bg: str) -> str | None:
    """Devuelve un mensaje de error si la combinación de colores no se podría escanear bien."""
    if not (HEX.match(fg) and HEX.match(bg)):
        return "Los colores no tienen un formato válido."
    lf, lb = _lum(fg), _lum(bg)
    if lf >= lb:
        return "El color del código debe ser más oscuro que el fondo; si no, muchos teléfonos no lo leen."
    if (lb + 0.05) / (lf + 0.05) < 3.5:
        return "Los colores tienen poco contraste y el código podría no leerse. Elige un color más oscuro o un fondo más claro."
    return None


@lru_cache(maxsize=64)
def _font(px: int):
    for path in FONT_PATHS:
        try:
            return ImageFont.truetype(path, px)
        except OSError:
            continue
    try:
        return ImageFont.load_default(size=px)
    except TypeError:  # Pillow antiguo
        return ImageFont.load_default()


def layout(data: str, *, fg=DEFAULT_FG, bg=DEFAULT_BG, logo: bytes | None = None,
           frame: str = "", mark: str = "") -> dict:
    """Calcula el diseño en módulos. mark = texto de marca de agua (plan gratis)."""
    fg, bg = fg or DEFAULT_FG, bg or DEFAULT_BG
    qr = segno.make(data, error="h" if logo else "m")
    matrix = [list(row) for row in qr.matrix]
    n, quiet = len(matrix), 4
    pad = 1.5 if frame else 0                      # grosor del marco
    w = n + 2 * quiet + 2 * pad
    qr_x = qr_y = pad + quiet
    h = qr_y + n + quiet
    els = [("rect", 0, 0, w, 0, bg)]               # alto del fondo se completa al final
    if frame:
        els.append(("frame", pad / 2, pad / 2, w - pad, 0, fg))
    els.append(("modules", qr_x, qr_y, matrix, fg))
    if logo:
        lg = Image.open(io.BytesIO(logo)).convert("RGBA")
        side = n * 0.22
        ratio = lg.width / lg.height
        lw, lh = (side, side / ratio) if ratio >= 1 else (side * ratio, side)
        box = 1.0
        bx, by = qr_x + (n - lw) / 2 - box, qr_y + (n - lh) / 2 - box
        els.append(("rect", bx, by, lw + 2 * box, lh + 2 * box, bg))
        els.append(("image", bx + box, by + box, lw, lh, logo))
    if frame:
        band = max(4.0, w * 0.13)
        els.append(("rect", 0, h, w, band + pad, fg))
        els.append(("text", w / 2, h + band * 0.62, band * 0.42, bg, frame, w * 0.86))
        h += band + pad
        els[1] = ("frame", pad / 2, pad / 2, w - pad, h - pad, fg)
    els[0] = ("rect", 0, 0, w, h, bg)
    if mark:
        band = max(3.0, w * 0.09)
        els.append(("rect", 0, h, w, band, "#ffffff"))
        els.append(("text", w / 2, h + band * 0.62, band * 0.36, MARK_COLOR, mark, w * 0.9))
        h += band
    return {"w": w, "h": h, "els": els, "pad": pad}


def to_png(lay: dict, scale: int = 12) -> bytes:
    W, H = round(lay["w"] * scale), round(lay["h"] * scale)
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    s = lambda v: round(v * scale)  # noqa: E731
    for el in lay["els"]:
        kind = el[0]
        if kind == "rect":
            _, x, y, w, h, col = el
            d.rectangle([s(x), s(y), s(x + w) - 1, s(y + h) - 1], fill=col)
        elif kind == "frame":
            _, x, y, w, h, col = el
            d.rounded_rectangle([s(x), s(y), s(x + w), s(y + h)], radius=s(1.5),
                                outline=col, width=max(1, s(lay["pad"])))
        elif kind == "modules":
            _, ox, oy, matrix, col = el
            for r, row in enumerate(matrix):
                for c, on in enumerate(row):
                    if on:
                        d.rectangle([s(ox + c), s(oy + r), s(ox + c + 1) - 1, s(oy + r + 1) - 1], fill=col)
        elif kind == "image":
            _, x, y, w, h, raw = el
            lg = Image.open(io.BytesIO(raw)).convert("RGBA").resize((max(1, s(w)), max(1, s(h))), Image.LANCZOS)
            img.paste(lg, (s(x), s(y)), lg)
        elif kind == "text":
            _, cx, baseline, size, col, text, max_w = el
            px = max(8, s(size))
            font = _font(px)
            while px > 8 and d.textlength(text, font=font) > s(max_w):
                px -= 1
                font = _font(px)
            d.text((s(cx), s(baseline)), text, fill=col, font=font, anchor="ms")
    out = io.BytesIO()
    img.save(out, "PNG", optimize=True)
    return out.getvalue()


def to_svg(lay: dict) -> bytes:
    f = lambda v: f"{v:.3f}".rstrip("0").rstrip(".")  # noqa: E731
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {f(lay["w"])} {f(lay["h"])}" '
             f'width="{f(lay["w"] * 10)}" height="{f(lay["h"] * 10)}" shape-rendering="crispEdges">']
    for el in lay["els"]:
        kind = el[0]
        if kind == "rect":
            _, x, y, w, h, col = el
            parts.append(f'<rect x="{f(x)}" y="{f(y)}" width="{f(w)}" height="{f(h)}" fill="{col}"/>')
        elif kind == "frame":
            _, x, y, w, h, col = el
            parts.append(f'<rect x="{f(x)}" y="{f(y)}" width="{f(w)}" height="{f(h)}" rx="1.5" fill="none" '
                         f'stroke="{col}" stroke-width="{f(lay["pad"])}" shape-rendering="geometricPrecision"/>')
        elif kind == "modules":
            _, ox, oy, matrix, col = el
            d = "".join(f"M{f(ox + c)} {f(oy + r)}h1v1h-1z" for r, row in enumerate(matrix)
                        for c, on in enumerate(row) if on)
            parts.append(f'<path fill="{col}" d="{d}"/>')
        elif kind == "image":
            _, x, y, w, h, raw = el
            parts.append(f'<image x="{f(x)}" y="{f(y)}" width="{f(w)}" height="{f(h)}" '
                         f'href="data:image/png;base64,{base64.b64encode(raw).decode()}"/>')
        elif kind == "text":
            _, cx, baseline, size, col, text, max_w = el
            parts.append(f'<text x="{f(cx)}" y="{f(baseline)}" font-size="{f(size)}" fill="{col}" '
                         f'font-family="Arial, Helvetica, sans-serif" font-weight="700" text-anchor="middle" '
                         f'textLength="{f(min(max_w, len(text) * size * 0.62))}" lengthAdjust="spacingAndGlyphs" '
                         f'shape-rendering="geometricPrecision">{escape(text)}</text>')
    parts.append("</svg>")
    return "".join(parts).encode()


def to_pdf(lay: dict) -> bytes:
    img = Image.open(io.BytesIO(to_png(lay, scale=30))).convert("RGB")
    out = io.BytesIO()
    img.save(out, "PDF", resolution=300)
    return out.getvalue()


def render(fmt: str, data: str, **design) -> bytes:
    lay = layout(data, **design)
    return {"png": to_png, "svg": to_svg, "pdf": to_pdf}[fmt](lay)
