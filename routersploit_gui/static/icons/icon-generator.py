#!/usr/bin/env python3
"""
Generate placeholder icons for RouterSploit GUI PWA
"""

import os
from pathlib import Path

def create_svg_icon(size: int) -> str:
    """Create an SVG icon for the given size."""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">
    <defs>
        <linearGradient id="grad1" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:#00ffff;stop-opacity:1" />
            <stop offset="100%" style="stop-color:#ff00ff;stop-opacity:1" />
        </linearGradient>
    </defs>
    
    <!-- Background -->
    <rect width="{size}" height="{size}" fill="#0a0a0a"/>
    
    <!-- Shield outline -->
    <path d="M{size//4} {size//6} L{size*3//4} {size//6} L{size*3//4} {size//2} L{size//2} {size*5//6} L{size//4} {size//2} Z" 
          fill="url(#grad1)" stroke="#00ffff" stroke-width="2"/>
    
    <!-- Center circle -->
    <circle cx="{size//2}" cy="{size//2}" r="{size//8}" fill="#00ffff" opacity="0.8"/>
    
    <!-- Text -->
    <text x="{size//2}" y="{size*3//4}" text-anchor="middle" fill="#00ffff" font-family="monospace" font-size="{size//6}">RS</text>
</svg>"""

def generate_icons():
    """Generate all required icon sizes."""
    sizes = [72, 96, 128, 144, 152, 192, 384, 512]
    
    icons_dir = Path(__file__).parent
    icons_dir.mkdir(exist_ok=True)
    
    for size in sizes:
        svg_content = create_svg_icon(size)
        svg_path = icons_dir / f"icon-{size}x{size}.svg"
        
        with open(svg_path, 'w') as f:
            f.write(svg_content)
        
        print(f"Generated {svg_path}")

if __name__ == "__main__":
    generate_icons() 