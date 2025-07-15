#!/usr/bin/env python3
"""
Test script to verify the frontend fixes for RouterSploit GUI
"""

import requests
import json
import time
from pathlib import Path

def test_server_running():
    """Test if the server is running and responding."""
    try:
        response = requests.get('http://127.0.0.1:5000', timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def test_static_files():
    """Test if static files are accessible."""
    files_to_test = [
        '/static/css/style.css',
        '/static/js/app.js',
        '/static/js/effects.js',
        '/static/js/sound-generator.js',
        '/static/manifest.json',
        '/sw.js'
    ]
    
    results = {}
    for file_path in files_to_test:
        try:
            response = requests.get(f'http://127.0.0.1:5000{file_path}', timeout=5)
            results[file_path] = response.status_code == 200
        except requests.RequestException:
            results[file_path] = False
    
    return results

def test_api_endpoints():
    """Test API endpoints."""
    endpoints_to_test = [
        '/api/modules',
        '/api/auto-own/status'
    ]
    
    results = {}
    for endpoint in endpoints_to_test:
        try:
            response = requests.get(f'http://127.0.0.1:5000{endpoint}', timeout=5)
            results[endpoint] = response.status_code == 200
        except requests.RequestException:
            results[endpoint] = False
    
    return results

def test_file_structure():
    """Test if required files exist."""
    required_files = [
        'routersploit_gui/templates/index.html',
        'routersploit_gui/static/css/style.css',
        'routersploit_gui/static/js/app.js',
        'routersploit_gui/static/js/effects.js',
        'routersploit_gui/static/js/sound-generator.js',
        'routersploit_gui/static/manifest.json',
        'routersploit_gui/static/sw.js'
    ]
    
    results = {}
    for file_path in required_files:
        results[file_path] = Path(file_path).exists()
    
    return results

def check_html_elements():
    """Check if HTML contains required elements."""
    html_path = Path('routersploit_gui/templates/index.html')
    if not html_path.exists():
        return {'error': 'HTML template not found'}
    
    content = html_path.read_text()
    
    required_elements = [
        'id="startAutoOwnBtn"',
        'id="autoOwnTarget"',
        'id="autoOwnVerbose"',
        'id="autoOwnDebug"',
        'id="openaiApiKey"',
        'id="saveApiKeyBtn"',
        'id="targetHistorySelect"',
        'matrix-rain',
        'particles',
        'glitch',
        'holographic'
    ]
    
    results = {}
    for element in required_elements:
        results[element] = element in content
    
    return results

def run_tests():
    """Run all tests and display results."""
    print("🧪 Testing RouterSploit GUI Frontend Fixes")
    print("=" * 60)
    
    # Test file structure
    print("\n📁 Testing File Structure:")
    file_results = test_file_structure()
    for file_path, exists in file_results.items():
        status = "✅" if exists else "❌"
        print(f"   {status} {file_path}")
    
    # Test HTML elements
    print("\n🔍 Testing HTML Elements:")
    html_results = check_html_elements()
    if 'error' in html_results:
        print(f"   ❌ {html_results['error']}")
    else:
        for element, found in html_results.items():
            status = "✅" if found else "❌"
            print(f"   {status} {element}")
    
    # Test server (if running)
    print("\n🌐 Testing Server:")
    if test_server_running():
        print("   ✅ Server is running on http://127.0.0.1:5000")
        
        # Test static files
        print("\n📦 Testing Static Files:")
        static_results = test_static_files()
        for file_path, accessible in static_results.items():
            status = "✅" if accessible else "❌"
            print(f"   {status} {file_path}")
        
        # Test API endpoints
        print("\n🔌 Testing API Endpoints:")
        api_results = test_api_endpoints()
        for endpoint, accessible in api_results.items():
            status = "✅" if accessible else "❌"
            print(f"   {status} {endpoint}")
    else:
        print("   ⚠️  Server is not running")
        print("   💡 Run 'python demo.py' to start the server")
    
    # Summary
    print("\n📊 Test Summary:")
    all_files_exist = all(file_results.values())
    all_elements_found = all(html_results.values()) if 'error' not in html_results else False
    
    print(f"   📁 File Structure: {'✅ PASS' if all_files_exist else '❌ FAIL'}")
    print(f"   🔍 HTML Elements: {'✅ PASS' if all_elements_found else '❌ FAIL'}")
    
    if test_server_running():
        all_static_ok = all(test_static_files().values())
        all_api_ok = all(test_api_endpoints().values())
        print(f"   📦 Static Files: {'✅ PASS' if all_static_ok else '❌ FAIL'}")
        print(f"   🔌 API Endpoints: {'✅ PASS' if all_api_ok else '❌ FAIL'}")
    
    print("\n🎯 Frontend Fixes Status:")
    fixes_working = all_files_exist and all_elements_found
    if fixes_working:
        print("   🎉 All frontend fixes are properly implemented!")
        print("   🚀 Ready to launch the enhanced RouterSploit GUI")
    else:
        print("   ⚠️  Some issues detected - check the results above")

if __name__ == "__main__":
    run_tests() 