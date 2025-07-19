#!/usr/bin/env python3
"""Simple HTTP server to test the ghosting effect."""

import http.server
import socketserver
import os
import webbrowser
from pathlib import Path

PORT = 8000

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(Path(__file__).parent), **kwargs)

    def end_headers(self):
        # Disable caching to ensure CSS changes are loaded
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

def main():
    os.chdir(Path(__file__).parent)
    
    with socketserver.TCPServer(("", PORT), CustomHTTPRequestHandler) as httpd:
        print(f"🚀 Test server starting on http://localhost:{PORT}")
        print(f"📁 Serving from: {Path.cwd()}")
        print(f"🧪 Test page: http://localhost:{PORT}/test_ghosting.html")
        print("🔄 Cache disabled - CSS changes will be loaded immediately")
        print("Press Ctrl+C to stop")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n👋 Server stopped")

if __name__ == "__main__":
    main()