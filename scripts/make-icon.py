"""Generate the MobileCheck app icon source (1024x1024 PNG).

On-brand: ARGUS dark tile, C-LAB cyan mark = a phone (portrait handset) with a
check (the '*-check' family motif — computer-check uses a monitor, this uses a
phone). Rendered at 4x and downscaled for clean edges.
Run: python3 scripts/make-icon.py  ->  build/icon-source.png
Then: npx tauri icon build/icon-source.png
"""
from PIL import Image, ImageDraw, ImageFilter
from pathlib import Path

S = 4096            # supersample canvas
OUT = 1024
CYAN = (91, 227, 195, 255)     # ARGUS C-LAB cyan in sRGB (#5be3c3)
BG_TOP = (16, 22, 27, 255)     # #10161b
BG_BOT = (8, 11, 14, 255)      # #080b0e

img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

def sc(v):  # scale a 1024-space value to the supersample canvas
    return int(v * S / 1024)

# --- rounded tile with vertical gradient -----------------------------------
margin = sc(76)
radius = sc(228)
tile = Image.new("RGBA", (S, S), (0, 0, 0, 0))
grad = Image.new("RGBA", (1, S), (0, 0, 0, 0))
for y in range(S):
    t = y / S
    grad.putpixel((0, y), tuple(int(BG_TOP[i] + (BG_BOT[i] - BG_TOP[i]) * t) for i in range(4)))
grad = grad.resize((S, S))
mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(mask).rounded_rectangle([margin, margin, S - margin, S - margin], radius=radius, fill=255)
tile.paste(grad, (0, 0), mask)
# subtle cyan hairline border
ImageDraw.Draw(tile).rounded_rectangle(
    [margin, margin, S - margin, S - margin], radius=radius, outline=(91, 227, 195, 60), width=sc(3)
)
img = Image.alpha_composite(img, tile)
d = ImageDraw.Draw(img)

# --- the mark: portrait phone + check --------------------------------------
mark = Image.new("RGBA", (S, S), (0, 0, 0, 0))
m = ImageDraw.Draw(mark)
stroke = sc(46)

# phone body (portrait rounded-rect outline), centered on x=512
px0, py0, px1, py1 = sc(366), sc(232), sc(658), sc(792)
m.rounded_rectangle([px0, py0, px1, py1], radius=sc(74), outline=CYAN, width=stroke)

# speaker slit near the top
slit_w = sc(70)
m.rounded_rectangle(
    [sc(512) - slit_w, sc(286), sc(512) + slit_w, sc(286) + sc(16)],
    radius=sc(8), fill=CYAN,
)

# home indicator near the bottom
hi_w = sc(80)
m.rounded_rectangle(
    [sc(512) - hi_w, sc(742), sc(512) + hi_w, sc(742) + sc(18)],
    radius=sc(9), fill=CYAN,
)

# check mark centered in the screen, with round caps/joints
cw = sc(58)
pts = [(sc(424), sc(512)), (sc(496), sc(584)), (sc(610), sc(446))]
m.line(pts, fill=CYAN, width=cw, joint="curve")
for (qx, qy) in [pts[0], pts[2]]:
    r = cw // 2
    m.ellipse([qx - r, qy - r, qx + r, qy + r], fill=CYAN)

# soft glow under the mark
glow = mark.filter(ImageFilter.GaussianBlur(sc(14)))
img = Image.alpha_composite(img, glow)
img = Image.alpha_composite(img, mark)

# --- downscale + save -------------------------------------------------------
out = img.resize((OUT, OUT), Image.LANCZOS)
build = Path(__file__).resolve().parent.parent / "build"
build.mkdir(exist_ok=True)
dest = build / "icon-source.png"
out.save(dest)
print("wrote", dest)
