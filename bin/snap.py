#!/usr/bin/env python3
"""Screenshot the scan TUI as a PNG.

Runs scan in a detached tmux session at a fixed size, waits, optionally sends keys,
captures the pane with its ANSI styles, renders the cells to HTML on a fixed cell grid,
and screenshots that page with headless Chrome. The palette is kitty's default.

    bin/snap.py example.com -o /tmp/scan.png --cols 200 --rows 56 --wait 8 --keys Tab Enter
"""

import argparse
import html
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata

FONT_PX = 16
CELL_W = FONT_PX * 0.6
CELL_H = round(FONT_PX * 1.25)
PAD = 12

FG = "#dddddd"
BG = "#2e3436"  # herdr/kitty default background, so unpainted cells show as they do live
ANSI16 = [
    "#000000", "#cc0403", "#19cb00", "#cecb00", "#0d73cc", "#cb1ed1", "#0dcdcd", "#dddddd",
    "#767676", "#f2201f", "#23fd00", "#fffd00", "#1a8fff", "#fd28ff", "#14ffff", "#ffffff",
]


def xterm256(n):
    if n < 16:
        return ANSI16[n]
    if n < 232:
        n -= 16
        steps = [0, 95, 135, 175, 215, 255]
        return "#%02x%02x%02x" % (steps[n // 36], steps[(n // 6) % 6], steps[n % 6])
    level = 8 + (n - 232) * 10
    return "#%02x%02x%02x" % (level, level, level)


class Style:
    def __init__(self):
        self.reset()

    def reset(self):
        self.fg = None
        self.bg = None
        self.bold = self.dim = self.italic = self.underline = self.reverse = False

    def key(self):
        return (self.fg, self.bg, self.bold, self.dim, self.italic, self.underline, self.reverse)

    def apply(self, params):
        codes = [int(p) if p else 0 for p in params.split(";")] if params else [0]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                self.reset()
            elif c == 1:
                self.bold = True
            elif c == 2:
                self.dim = True
            elif c == 3:
                self.italic = True
            elif c == 4:
                self.underline = True
            elif c == 7:
                self.reverse = True
            elif c == 22:
                self.bold = self.dim = False
            elif c == 23:
                self.italic = False
            elif c == 24:
                self.underline = False
            elif c == 27:
                self.reverse = False
            elif 30 <= c <= 37:
                self.fg = ANSI16[c - 30]
            elif 90 <= c <= 97:
                self.fg = ANSI16[c - 90 + 8]
            elif 40 <= c <= 47:
                self.bg = ANSI16[c - 40]
            elif 100 <= c <= 107:
                self.bg = ANSI16[c - 100 + 8]
            elif c == 39:
                self.fg = None
            elif c == 49:
                self.bg = None
            elif c in (38, 48) and i + 1 < len(codes):
                if codes[i + 1] == 5 and i + 2 < len(codes):
                    color = xterm256(codes[i + 2])
                    i += 2
                elif codes[i + 1] == 2 and i + 4 < len(codes):
                    color = "#%02x%02x%02x" % tuple(codes[i + 2:i + 5])
                    i += 4
                else:
                    color = None
                if c == 38:
                    self.fg = color
                else:
                    self.bg = color
            i += 1

    def css(self):
        fg, bg = self.fg or FG, self.bg
        if self.reverse:
            fg, bg = (bg or BG), fg
        parts = [f"color:{fg}"]
        if bg:
            parts.append(f"background:{bg}")
        if self.bold:
            parts.append("font-weight:bold")
        if self.dim:
            parts.append("opacity:0.6")
        if self.italic:
            parts.append("font-style:italic")
        if self.underline:
            parts.append("text-decoration:underline")
        return ";".join(parts)


def cell_width(ch):
    if unicodedata.combining(ch) or ch in "‍️":
        return 0
    if unicodedata.east_asian_width(ch) in ("W", "F"):
        return 2
    return 1


def parse_line(line, style):
    """ANSI text -> list of (char, width, css). `style` carries over from the previous line:
    tmux's capture only emits SGR changes, so a background set on row 0 is never repeated."""
    cells = []
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\x1b" and i + 1 < len(line) and line[i + 1] == "[":
            j = i + 2
            while j < len(line) and not ("@" <= line[j] <= "~"):
                j += 1
            if j < len(line) and line[j] == "m":
                style.apply(line[i + 2:j])
            i = j + 1
            continue
        width = cell_width(ch)
        if width == 0 and cells:
            prev = cells[-1]
            cells[-1] = (prev[0] + ch, prev[1], prev[2])
        elif width > 0:
            cells.append((ch, width, style.css()))
        i += 1
    return cells


def to_html(lines, cols, rows):
    out = []
    style = Style()
    for line in lines[:rows]:
        cells = parse_line(line, style)
        used = sum(w for _, w, _ in cells)
        row = []
        for text, width, css in cells:
            row.append(f'<span class="c" style="{css};width:{width * CELL_W}px">{html.escape(text)}</span>')
        if used < cols:
            row.append(f'<span class="c" style="width:{(cols - used) * CELL_W}px"></span>')
        out.append(f'<div class="r">{"".join(row)}</div>')
    width = cols * CELL_W + 2 * PAD
    height = rows * CELL_H + 2 * PAD
    page = f"""<!doctype html><html><head><meta charset="utf-8"><style>
html,body{{margin:0;background:{BG};}}
body{{padding:{PAD}px;width:{cols * CELL_W}px;}}
.r{{height:{CELL_H}px;line-height:{CELL_H}px;white-space:pre;overflow:hidden;
font-family:"FiraCode Nerd Font Mono","DejaVu Sans Mono","Noto Color Emoji",monospace;
font-size:{FONT_PX}px;font-variant-ligatures:none;color:{FG};}}
.c{{display:inline-block;height:{CELL_H}px;overflow:visible;vertical-align:top;text-align:center;}}
</style></head><body>{"".join(out)}</body></html>"""
    return page, int(width), int(height)


def tmux(*args, check=True):
    return subprocess.run(["tmux", *args], check=check, capture_output=True, text=True)


def capture(cmd, cols, rows, wait, keys, key_wait):
    session = f"scan-snap-{os.getpid()}"
    env_cmd = f"env TERM=xterm-256color COLORTERM=truecolor {cmd}"
    tmux("new-session", "-d", "-s", session, "-x", str(cols), "-y", str(rows), env_cmd)
    try:
        tmux("set-option", "-t", session, "default-terminal", "tmux-256color", check=False)
        time.sleep(wait)
        for key in keys:
            tmux("send-keys", "-t", session, key)
            time.sleep(key_wait)
        return tmux("capture-pane", "-t", session, "-e", "-p").stdout.split("\n")
    finally:
        tmux("kill-session", "-t", session, check=False)


def screenshot(page, width, height, out):
    chrome = shutil.which("google-chrome") or shutil.which("chromium")
    if not chrome:
        sys.exit("snap: no google-chrome or chromium on PATH")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "snap.html")
        with open(path, "w") as f:
            f.write(page)
        subprocess.run(
            [chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
             f"--user-data-dir={tmp}/profile", f"--window-size={width},{height}",
             f"--screenshot={os.path.abspath(out)}", f"file://{path}"],
            check=True, capture_output=True,
        )


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="target passed to scan")
    ap.add_argument("-o", "--output", default="snap.png", help="PNG path")
    ap.add_argument("--bin", default="target/debug/scan", help="scan binary")
    ap.add_argument("--cols", type=int, default=200)
    ap.add_argument("--rows", type=int, default=56)
    ap.add_argument("--wait", type=float, default=8.0, help="seconds before the first key or capture")
    ap.add_argument("--keys", nargs="*", default=[], help="tmux key names sent before capture (Tab Enter Down)")
    ap.add_argument("--key-wait", type=float, default=0.5, help="seconds after each key")
    ap.add_argument("--bg", default=BG, help="terminal default background for unpainted cells")
    ap.add_argument("--ansi", help="also write the raw ANSI capture here")
    args = ap.parse_args()

    globals()["BG"] = args.bg
    lines = capture(f"{args.bin} {args.target}", args.cols, args.rows, args.wait, args.keys, args.key_wait)
    if args.ansi:
        with open(args.ansi, "w") as f:
            f.write("\n".join(lines))
    page, width, height = to_html(lines, args.cols, args.rows)
    screenshot(page, width, height, args.output)
    print(os.path.abspath(args.output))


if __name__ == "__main__":
    main()
