#!/usr/bin/env python3
"""Render terminal text to a PNG screenshot with dark terminal style."""
import sys
from PIL import Image, ImageDraw, ImageFont

def render(text, output_path, title="Terminal"):
    lines = text.split('\n')
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 14)
    except OSError:
        font = ImageFont.load_default()

    line_height = 18
    padding = 20
    title_bar = 32
    width = max(max(len(l) for l in lines) * 9, 600) + padding * 2
    height = len(lines) * line_height + padding * 2 + title_bar

    img = Image.new('RGB', (width, height), (40, 42, 54))
    draw = ImageDraw.Draw(img)

    # Title bar
    draw.rectangle([0, 0, width, title_bar], fill=(30, 30, 40))
    draw.text((padding, 7), f"  {title}", fill=(180, 180, 200), font=font)
    # Window buttons
    for i, color in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        draw.ellipse([8 + i * 20, 9, 22 + i * 20, 23], fill=color)

    y = title_bar + padding // 2
    for line in lines:
        color = (248, 248, 242)  # default white
        if 'WARNING' in line or '***' in line:
            color = (255, 85, 85)  # red for warnings
        elif 'INFO' in line and 'Started' in line:
            color = (80, 250, 123)  # green for started
        elif 'IDLE' in line or 'Status:' in line:
            color = (139, 233, 253)  # cyan for status
        elif 'DDoS DETECTED' in line or 'GPS SPOOF DETECTED' in line:
            color = (255, 121, 198)  # pink for detection status
        elif line.startswith('$') or line.startswith('fatima@'):
            color = (189, 147, 249)  # purple for prompt
        draw.text((padding, y), line, fill=color, font=font)
        y += line_height

    img.save(output_path)
    print(f"Saved: {output_path}")

if __name__ == '__main__':
    text = sys.stdin.read()
    output_path = sys.argv[1]
    title = sys.argv[2] if len(sys.argv) > 2 else "Terminal"
    render(text, output_path, title)
