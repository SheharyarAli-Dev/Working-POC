"""Render selected diagrams.net pages to standalone SVG using their source geometry.

This lightweight exporter preserves page dimensions, cells, labels, colors and
edge anchors from the editable .drawio document. Run from report/ with:

  python tools/drawio_source_export.py sources/ASENT_All_Diagrams.drawio

The resulting SVGs can be rasterized for the LaTeX report; edit the source in
diagrams.net and rerun this exporter to refresh them.
"""
from __future__ import annotations

import html
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


PAGES = {
    "01": "asent-use-cases.svg",
    "02": "asent-architecture.svg",
    "06": "satra-assurance-flow.svg",
    "07": "sable-assurance-flow.svg",
    "08": "sable-domain-model.svg",
    "09": "shared-final-gate.svg",
}


def parse_style(text: str) -> dict[str, str]:
    return dict(part.split("=", 1) for part in text.split(";") if "=" in part)


def anchor(cell: ET.Element, x_key: str, y_key: str, default: tuple[float, float], edge_style: dict[str, str] | None = None) -> tuple[float, float]:
    geo = cell.find("mxGeometry")
    x, y = float(geo.get("x", 0)), float(geo.get("y", 0))
    w, h = float(geo.get("width", 0)), float(geo.get("height", 0))
    style = edge_style or parse_style(cell.get("style", ""))
    px = float(style.get(x_key, default[0]))
    py = float(style.get(y_key, default[1]))
    return x + w * px, y + h * py


def text_html(value: str) -> str:
    # Keep source-authored emphasis and line breaks while sanitizing arbitrary
    # tag/attribute content into a small SVG foreignObject HTML subset.
    value = value.replace("<hr>", '<hr style="border:0;border-top:1px solid #c5d2dc;width:100%"/>')
    value = re.sub(r"<br\s*/?>", "<br/>", value, flags=re.I)
    value = re.sub(r"</?b>", lambda m: "<strong>" if m.group(0).startswith("<b") else "</strong>", value, flags=re.I)
    value = re.sub(r"<[^>]*>", "", value) if "<" in value and not re.search(r"<(?:br|hr|strong)", value) else value
    return value


def render(page: ET.Element) -> str:
    model = page.find("mxGraphModel")
    width, height = float(model.get("pageWidth", 1600)), float(model.get("pageHeight", 1000))
    cells = {c.get("id"): c for c in page.findall(".//mxCell")}
    vertices = [c for c in cells.values() if c.get("vertex") == "1" and c.find("mxGeometry") is not None]
    edges = [c for c in cells.values() if c.get("edge") == "1" and c.find("mxGeometry") is not None]
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xhtml="http://www.w3.org/1999/xhtml" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
             '<defs><marker id="arrow" markerWidth="10" markerHeight="8" refX="9" refY="4" orient="auto"><path d="M0,0 L10,4 L0,8 z" fill="#526579"/></marker></defs>',
             f'<rect width="{width}" height="{height}" fill="#ffffff"/>']
    # Edges first, as in diagrams.net, so arrows remain behind the shapes.
    for edge in edges:
        src, dst = cells.get(edge.get("source")), cells.get(edge.get("target"))
        if src is None or dst is None:
            continue
        edge_style = parse_style(edge.get("style", ""))
        sx, sy = anchor(src, "exitX", "exitY", (0.5, 0.5), edge_style)
        tx, ty = anchor(dst, "entryX", "entryY", (0.5, 0.5), edge_style)
        dx, dy = tx - sx, ty - sy
        # Use source/target anchors from the draw.io file and a gentle cubic
        # curve for legible connectors without drawing through unrelated nodes.
        cx1, cy1 = sx + dx * 0.38, sy + dy * 0.12
        cx2, cy2 = tx - dx * 0.38, ty - dy * 0.12
        st = edge_style
        color = st.get("strokeColor", "#526579")
        sw = st.get("strokeWidth", "1.8")
        dash = ' stroke-dasharray="7 5"' if st.get("dashed") == "1" else ""
        marker = ' marker-end="url(#arrow)"' if st.get("endArrow", "block") != "none" else ""
        parts.append(f'<path d="M{sx:g},{sy:g} C{cx1:g},{cy1:g} {cx2:g},{cy2:g} {tx:g},{ty:g}" fill="none" stroke="{color}" stroke-width="{sw}"{dash}{marker}/>')
    for cell in vertices:
        geo = cell.find("mxGeometry")
        x, y, w, h = (float(geo.get(k, 0)) for k in ("x", "y", "width", "height"))
        st = parse_style(cell.get("style", ""))
        shape = st.get("shape", "ellipse" if "ellipse" in cell.get("style", "") else "rect")
        fill = st.get("fillColor", "#ffffff")
        stroke = st.get("strokeColor", "#526579")
        font = st.get("fontColor", "#243746")
        fs = float(st.get("fontSize", "15"))
        sw = st.get("strokeWidth", "1.5")
        opacity = st.get("opacity", "100")
        if st.get("strokeColor") == "none":
            stroke = "none"
        if st.get("fillColor") == "none":
            fill = "none"
        if shape == "umlActor":
            cx, cy = x + w / 2, y + h * 0.3
            parts.append(f'<circle cx="{cx:g}" cy="{cy:g}" r="16" fill="none" stroke="{stroke}" stroke-width="3"/><path d="M{cx:g},{cy+16:g} v42 M{cx-26:g},{cy+35:g} h52 M{cx:g},{cy+58:g} l-24,35 M{cx:g},{cy+58:g} l24,35" fill="none" stroke="{stroke}" stroke-width="3"/>')
            label_y = y + h - 28
            parts.append(f'<foreignObject x="{x:g}" y="{label_y:g}" width="{w:g}" height="28"><xhtml:div style="font:600 {fs}px Arial,sans-serif;text-align:center;color:{font}">{text_html(cell.get("value", ""))}</xhtml:div></foreignObject>')
            continue
        if shape == "rhombus":
            pts = f"{x+w/2:g},{y:g} {x+w:g},{y+h/2:g} {x+w/2:g},{y+h:g} {x:g},{y+h/2:g}"
            parts.append(f'<polygon points="{pts}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}" opacity="{float(opacity)/100:g}"/>')
        elif "ellipse" in cell.get("style", ""):
            parts.append(f'<ellipse cx="{x+w/2:g}" cy="{y+h/2:g}" rx="{w/2:g}" ry="{h/2:g}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}" opacity="{float(opacity)/100:g}"/>')
        else:
            radius = 12 if st.get("rounded") == "1" else 2
            parts.append(f'<rect x="{x:g}" y="{y:g}" width="{w:g}" height="{h:g}" rx="{radius}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}" opacity="{float(opacity)/100:g}"/>')
        align = st.get("align", "center")
        valign = st.get("verticalAlign", "middle")
        pad = 9
        tx = x + pad if align == "left" else x + w - pad if align == "right" else x
        width_text = max(w - 2 * pad, 1)
        text_align = "left" if align == "left" else "right" if align == "right" else "center"
        top = y + 2 if valign == "top" else y + 2
        height_text = max(h - 4, 1)
        weight = 700 if st.get("fontStyle", "0") in ("1", "3") else 400
        text = text_html(cell.get("value", ""))
        parts.append(f'<foreignObject x="{tx:g}" y="{top:g}" width="{width_text:g}" height="{height_text:g}"><xhtml:div xmlns:xhtml="http://www.w3.org/1999/xhtml" style="box-sizing:border-box;width:100%;height:100%;padding:{pad if align != "center" else 5}px;display:flex;flex-direction:column;justify-content:{"flex-start" if valign == "top" else "center"};align-items:{"flex-start" if align == "left" else "flex-end" if align == "right" else "center"};overflow:hidden;text-align:{text_align};font:{weight} {fs}px Arial,sans-serif;line-height:1.25;color:{font};word-break:normal">{text}</xhtml:div></foreignObject>')
    parts.append("</svg>")
    return "\n".join(parts)


def render_png(page: ET.Element, destination: Path) -> None:
    """Rasterize the same source cells at 2x with Pillow for reliable TeX use."""
    model = page.find("mxGraphModel")
    width, height = int(float(model.get("pageWidth", 1600))), int(float(model.get("pageHeight", 1000)))
    scale = 2
    image = Image.new("RGB", (width * scale, height * scale), "white")
    draw = ImageDraw.Draw(image)
    cells = {c.get("id"): c for c in page.findall(".//mxCell")}
    vertices = [c for c in cells.values() if c.get("vertex") == "1" and c.find("mxGeometry") is not None]
    edges = [c for c in cells.values() if c.get("edge") == "1" and c.find("mxGeometry") is not None]
    font_path = Path(r"C:\Windows\Fonts")

    def font(size: float, bold: bool = False) -> ImageFont.FreeTypeFont:
        file = "arialbd.ttf" if bold else "arial.ttf"
        return ImageFont.truetype(str(font_path / file), max(10, int(size * scale)))

    def xy(cell: ET.Element, x_key: str, y_key: str, default: tuple[float, float]) -> tuple[int, int]:
        a, b = anchor(cell, x_key, y_key, default)
        return int(a * scale), int(b * scale)

    # Connectors use source/target anchors from diagrams.net and a cubic route.
    for edge in edges:
        src, dst = cells.get(edge.get("source")), cells.get(edge.get("target"))
        if src is None or dst is None:
            continue
        edge_style = parse_style(edge.get("style", ""))
        sx0, sy0 = anchor(src, "exitX", "exitY", (0.5, 0.5), edge_style)
        tx0, ty0 = anchor(dst, "entryX", "entryY", (0.5, 0.5), edge_style)
        sx, sy, tx, ty = (int(v*scale) for v in (sx0, sy0, tx0, ty0))
        dx, dy = tx - sx, ty - sy
        c1, c2 = (sx + dx * .38, sy + dy * .12), (tx - dx * .38, ty - dy * .12)
        points = []
        for i in range(31):
            t = i / 30
            u = 1 - t
            px = u**3*sx + 3*u*u*t*c1[0] + 3*u*t*t*c2[0] + t**3*tx
            py = u**3*sy + 3*u*u*t*c1[1] + 3*u*t*t*c2[1] + t**3*ty
            points.append((int(px), int(py)))
        st = edge_style
        color = st.get("strokeColor", "#526579")
        draw.line(points, fill=color, width=max(2, int(float(st.get("strokeWidth", 1.8)) * scale)))
        if st.get("endArrow", "block") != "none":
            ex, ey = points[-1]
            ax, ay = points[-3]
            import math
            angle = math.atan2(ey - ay, ex - ax)
            length, spread = 11 * scale, 5 * scale
            left = (ex - length * math.cos(angle) + spread * math.sin(angle), ey - length * math.sin(angle) - spread * math.cos(angle))
            right = (ex - length * math.cos(angle) - spread * math.sin(angle), ey - length * math.sin(angle) + spread * math.cos(angle))
            draw.polygon([(ex, ey), left, right], fill=color)

    for cell in vertices:
        geo = cell.find("mxGeometry")
        x, y, w, h = (float(geo.get(k, 0)) for k in ("x", "y", "width", "height"))
        box = (int(x*scale), int(y*scale), int((x+w)*scale), int((y+h)*scale))
        st = parse_style(cell.get("style", ""))
        fill, stroke = st.get("fillColor", "#ffffff"), st.get("strokeColor", "#526579")
        fill = "white" if fill == "none" else fill
        outline = None if stroke == "none" else stroke
        sw = max(1, int(float(st.get("strokeWidth", 1.5)) * scale))
        shape = st.get("shape", "ellipse" if "ellipse" in cell.get("style", "") else "rect")
        if shape == "umlActor":
            cx, cy = (box[0]+box[2])//2, box[1]+int((box[3]-box[1])*.3)
            pen = outline or "#526579"
            r=16*scale
            draw.ellipse((cx-r,cy-r,cx+r,cy+r),outline=pen,width=sw)
            draw.line((cx,cy+r,cx,cy+r+42*scale),fill=pen,width=sw)
            draw.line((cx-25*scale,cy+35*scale,cx+25*scale,cy+35*scale),fill=pen,width=sw)
            draw.line((cx,cy+r+42*scale,cx-22*scale,cy+r+78*scale),fill=pen,width=sw)
            draw.line((cx,cy+r+42*scale,cx+22*scale,cy+r+78*scale),fill=pen,width=sw)
        elif shape == "rhombus":
            pts=[((box[0]+box[2])//2,box[1]),(box[2],(box[1]+box[3])//2),((box[0]+box[2])//2,box[3]),(box[0],(box[1]+box[3])//2)]
            draw.polygon(pts,fill=fill,outline=outline)
            if outline: draw.line(pts+[pts[0]],fill=outline,width=sw)
        elif "ellipse" in cell.get("style", ""):
            draw.ellipse(box,fill=fill,outline=outline,width=sw)
        else:
            radius=12*scale if st.get("rounded")=="1" else 2*scale
            draw.rounded_rectangle(box,radius=radius,fill=fill,outline=outline,width=sw)
        if not cell.get("value"):
            continue
        raw=cell.get("value", "")
        raw=re.sub(r"<br\s*/?>", "\n", raw, flags=re.I)
        raw=re.sub(r"<hr\s*/?>", "\n", raw, flags=re.I)
        raw=html.unescape(re.sub(r"<[^>]+>", "", raw)).replace("\u00a0", " ")
        align=st.get("align", "center")
        valign=st.get("verticalAlign", "middle")
        fs=float(st.get("fontSize", "15"))*scale
        bold=st.get("fontStyle", "0") in ("1","3") or "<b>" in cell.get("value", "")
        # Draw.io is authored for screen scale. Enlarge labels moderately for
        # the report's landscape print figures while wrapping to the same boxes.
        f=font(fs/scale*1.4,bold)
        pad=10*scale
        max_width=max(30,box[2]-box[0]-2*pad)
        wrapped=[]
        for paragraph in raw.splitlines():
            words=paragraph.split()
            line=""
            for word in words:
                candidate=(line+" "+word).strip()
                if line and draw.textbbox((0,0),candidate,font=f)[2] > max_width:
                    wrapped.append(line); line=word
                else: line=candidate
            wrapped.append(line)
        text="\n".join(wrapped)
        bb=draw.multiline_textbbox((0,0),text,font=f,spacing=int(4*scale),align=align)
        tw,th=bb[2]-bb[0],bb[3]-bb[1]
        if align=="left": tx=box[0]+pad
        elif align=="right": tx=box[2]-pad-tw
        else: tx=box[0]+(box[2]-box[0]-tw)//2
        ty=box[1]+pad if valign=="top" else box[1]+(box[3]-box[1]-th)//2
        draw.multiline_text((tx,ty),text,font=f,fill=st.get("fontColor", "#243746"),spacing=int(4*scale),align=align)
    image.save(destination, optimize=True)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python tools/drawio_source_export.py <editable.drawio>")
    source = Path(sys.argv[1])
    root = ET.parse(source).getroot()
    out = Path("figures/asent")
    out.mkdir(parents=True, exist_ok=True)
    for prefix, filename in PAGES.items():
        page = next((p for p in root.findall("diagram") if p.get("name", "").startswith(prefix)), None)
        if page is None:
            raise SystemExit(f"missing diagrams.net source page {prefix}")
        (out / filename).write_text(render(page), encoding="utf-8")
        render_png(page, out / (Path(filename).stem + ".png"))
        print(f"{page.get('name')} -> {out / filename}")


if __name__ == "__main__":
    main()
