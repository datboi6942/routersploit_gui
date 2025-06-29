#!/usr/bin/env python3
"""Demo script for RouterSploit Web GUI."""

from routersploit_gui.web_gui import RouterSploitWebGUI

def main() -> None:
    """Demo the RouterSploit web GUI."""
    print("Starting RouterSploit Web GUI Demo...")
    print("This will start a web server on http://127.0.0.1:5000")
    print("Open your browser to access the GUI")
    print("Press Ctrl+C to stop")
    
    gui = RouterSploitWebGUI(host="127.0.0.1", port=5000)
    try:
        gui.run(debug=True)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        gui.cleanup()

if __name__ == "__main__":
    main() 