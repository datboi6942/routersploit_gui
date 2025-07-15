#!/usr/bin/env python3
"""
Simple test to verify auto-own button functionality.
"""

import requests
import time
import sys

def test_auto_own_button():
    """Test the auto-own button functionality via API."""
    
    base_url = "http://127.0.0.1:5000"
    
    print("🔍 Testing Auto-Own Button Functionality...")
    
    # Test 1: Check if server is running
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code == 200:
            print("✅ Server is running")
        else:
            print(f"❌ Server returned status {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Server is not accessible: {e}")
        return False
    
    # Test 2: Check if auto-own start endpoint exists
    try:
        test_data = {
            "target": "192.168.1.1",
            "verbose": True,
            "debug": True
        }
        
        response = requests.post(f"{base_url}/api/auto-own/start", json=test_data, timeout=10)
        print(f"📡 Auto-own start endpoint response: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Auto-own start endpoint working: {result}")
            return True
        else:
            print(f"⚠️ Auto-own start endpoint returned {response.status_code}")
            try:
                error_data = response.json()
                print(f"📝 Error details: {error_data}")
            except:
                print(f"📝 Response text: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Auto-own start endpoint error: {e}")
        return False

def main():
    """Main test function."""
    print("🚀 RouterSploit Auto-Own Button Test")
    print("="*50)
    
    # Wait a bit for server to start
    print("⏳ Waiting for server to start...")
    time.sleep(3)
    
    if test_auto_own_button():
        print("\n✅ Auto-Own button functionality test PASSED")
        print("\n🎯 Manual test instructions:")
        print("1. Open http://127.0.0.1:5000 in your browser")
        print("2. Click on the 'AUTO-OWN' tab")
        print("3. Enter target: 192.168.1.1")
        print("4. Check 'Verbose' and 'Debug' checkboxes")
        print("5. Click 'Start Auto-Own' button")
        print("6. Check browser console for debug messages")
        print("7. The button should work and show progress")
        
        return True
    else:
        print("\n❌ Auto-Own button functionality test FAILED")
        print("\n🔧 Troubleshooting:")
        print("- Check if the server is running on port 5000")
        print("- Verify the auto-own API endpoints are working")
        print("- Check browser console for JavaScript errors")
        print("- Ensure all HTML elements have correct IDs")
        
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 