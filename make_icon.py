from PIL import Image, ImageDraw

def make_frame(size):
    # アンチエイリアスのため4倍サイズで描いてリサイズ
    S = size * 4
    img = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    cx = cy = S // 2

    # 背景円（ダークネイビー）
    pad = S // 16
    d.ellipse([pad, pad, S-pad, S-pad], fill=(13, 17, 23, 255))

    # 外枠リング（青）
    bw = S // 14
    d.ellipse([pad, pad, S-pad, S-pad],
              outline=(88, 166, 255, 255), width=bw)

    # 軌道リング x3（緑、内側から）
    for ratio, alpha in [(0.28, 210), (0.46, 170), (0.64, 130)]:
        r = int(S * ratio)
        lw = max(2, S // 40)
        d.ellipse([cx-r, cy-r, cx+r, cy+r],
                  outline=(63, 185, 80, alpha), width=lw)

    # 中心ドット（明るい青）
    dr = S // 10
    d.ellipse([cx-dr, cy-dr, cx+dr, cy+dr], fill=(88, 166, 255, 255))
    # ドットのハイライト
    hr = S // 20
    d.ellipse([cx-hr*2, cy-hr*2, cx-hr//2, cy-hr//2],
              fill=(200, 230, 255, 160))

    return img.resize((size, size), Image.LANCZOS)

def make_ico():
    sizes = [256, 64, 48, 32, 16]
    frames = [make_frame(s) for s in sizes]
    frames[0].save(
        'netmonitor.ico',
        format='ICO',
        sizes=[(s, s) for s in sizes],
        append_images=frames[1:]
    )
    print('Icon generated: netmonitor.ico')

make_ico()
