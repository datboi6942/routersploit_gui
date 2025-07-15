#!/usr/bin/env python3
"""
Debug script for auto-own button functionality.
"""

import time
import threading
from routersploit_gui.web_gui import RouterSploitWebGUI

def test_autopwn_button():
    """Test the auto-own button functionality."""
    
    print("🚀 Starting RouterSploit GUI for auto-own button testing...")
    
    # Create GUI instance
    gui = RouterSploitWebGUI(host="127.0.0.1", port=5001)
    
    # Start the server in a separate thread
    server_thread = threading.Thread(target=lambda: gui.run(debug=True))
    server_thread.daemon = True
    server_thread.start()
    
    # Wait for server to start
    time.sleep(2)
    
    print("✅ Server started successfully on http://127.0.0.1:5001")
    print("\n🔍 Testing Auto-Own Button:")
    print("1. Open your browser and navigate to http://127.0.0.1:5001")
    print("2. Click on the 'AUTO-OWN' tab")
    print("3. Enter a target IP (e.g., 192.168.1.1)")
    print("4. Check the 'Verbose' and 'Debug' checkboxes")
    print("5. Click the 'Start Auto-Own' button")
    print("\n🎯 What to look for:")
    print("- Button should be clickable and not disabled")
    print("- Console output should show 'Start Auto-Own button clicked'")
    print("- Progress section should appear")
    print("- Auto-own process should start")
    
    print("\n⚠️  If button doesn't work, check browser console for JavaScript errors")
    print("📝 Press Ctrl+C to stop the server when done testing")
    
    try:
        # Keep the server running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")

if __name__ == "__main__":
    test_autopwn_button() 