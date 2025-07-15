#!/usr/bin/env python3
"""Demo script for the Auto-Own LLM feature."""

import os
import sys
import time
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from routersploit_gui import config
from routersploit_gui.tools import ToolManager, NmapScanner, MetasploitWrapper, ExploitDBWrapper
from routersploit_gui.llm_agent import AutoOwnAgent

def demo_auto_own():
    """Demonstrate the Auto-Own AI agent."""
    print("🤖 RouterSploit Auto-Own Demo")
    print("=" * 50)
    
    # Configuration check
    print("\n📋 Configuration Check:")
    print(f"  Auto-Own Enabled: {config.AUTO_OWN_ENABLED}")
    print(f"  OpenAI API Key: {'✅ Configured' if config.get_openai_api_key() else '❌ Not configured'}")
    print(f"  OpenAI Model: {config.OPENAI_MODEL}")
    print(f"  Results Directory: {config.AUTO_OWN_RESULTS_DIR}")
    
    # Check if API key is configured
    if not config.get_openai_api_key():
        print("\n❌ ERROR: OpenAI API key not configured!")
        print(f"Please add your API key to: {config.OPENAI_API_KEY_FILE}")
        return
    
    # Initialize the agent
    print("\n🤖 Initializing Auto-Own Agent...")
    agent = AutoOwnAgent()
    
    # Check available targets
    print("\n📊 Available targets from previous scans:")
    targets = agent.get_available_targets()
    if targets:
        for target in targets[:5]:  # Show first 5
            print(f"  • {target}")
    else:
        print("  No previous scan results found")
    
    # Run auto-own on localhost
    target = "127.0.0.1"
    print(f"\n🎯 Starting Auto-Own process on {target}...")
    print("This may take several minutes...")
    
    try:
        # Run the auto-own process
        results = agent.auto_own_target(target, verbose=True, debug=False)
        
        # Display results
        if "error" in results:
            print(f"\n❌ Auto-Own failed: {results['error']}")
        else:
            print(f"\n✅ Auto-Own completed successfully!")
            print(f"  Target: {results['target']}")
            print(f"  Iterations: {results['iterations']}")
            print(f"  Timestamp: {results['timestamp']}")
            
            # Show conversation summary
            history = results.get("conversation_history", [])
            print(f"  Conversation messages: {len(history)}")
            
            # Show final summary
            summary = results.get("final_summary", "")
            if summary:
                print(f"\n📝 Final Summary:")
                print(f"  {summary[:200]}{'...' if len(summary) > 200 else ''}")
    
    except Exception as e:
        print(f"\n❌ Auto-Own failed with exception: {str(e)}")
        import traceback
        traceback.print_exc()
    
    print("\n🎉 Auto-Own demo completed!")

def demo_tools():
    """Demo the individual tools."""
    print("\n🔧 Tool Demo")
    print("=" * 30)
    
    from routersploit_gui.tools import NmapScanner, MetasploitWrapper, ExploitDBWrapper
    
    # Test nmap scanner
    print("\n1. Testing Nmap Scanner...")
    scanner = NmapScanner()
    result = scanner.scan_target("127.0.0.1", "22,80,443")
    print(f"   Result: {result.get('status', 'unknown')}")
    print(f"   Ports found: {len(result.get('ports', []))}")
    
    # Test Metasploit wrapper
    print("\n2. Testing Metasploit Wrapper...")
    msf = MetasploitWrapper()
    exploits = msf.search_exploits("apache")
    print(f"   Exploits found: {len(exploits)}")
    
    # Test Exploit-DB wrapper
    print("\n3. Testing Exploit-DB Wrapper...")
    edb = ExploitDBWrapper()
    exploits = edb.search_exploits("ssh")
    print(f"   Exploits found: {len(exploits)}")

if __name__ == "__main__":
    print("RouterSploit Auto-Own Demo")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not Path("routersploit_gui").exists():
        print("❌ Please run this script from the project root directory")
        sys.exit(1)
    
    # Run tool demo first
    demo_tools()
    
    # Run auto-own demo
    demo_auto_own()
    
    print("\n✨ Demo completed! Check the web interface at http://127.0.0.1:5000")
    print("   The Auto-Own tab will be available in the web GUI.") 