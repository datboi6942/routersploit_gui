#!/usr/bin/env python3
"""Demo script for RouterSploit GUI."""

from routersploit_gui.module_loader import ModuleLoader


def main() -> None:
    """Demonstrate RouterSploit GUI functionality."""
    print("🛠️ RouterSploit GUI Demo")
    print("=" * 50)
    
    # Initialize module loader
    print("📦 Initializing module loader...")
    loader = ModuleLoader()
    
    # Discover modules
    print("🔍 Discovering RouterSploit modules...")
    modules = loader.discover_modules()
    print(f"✅ Found {len(modules)} modules")
    
    # Build module tree
    print("🌳 Building module tree...")
    tree = loader.build_tree()
    categories = list(tree.keys())
    print(f"✅ Organized into {len(categories)} categories: {categories}")
    
    # Show some example modules
    print("\n📋 Sample modules with options:")
    modules_with_opts = [m for m in modules if m.opts][:3]
    
    for i, module in enumerate(modules_with_opts, 1):
        print(f"\n{i}. {module.name}")
        print(f"   📂 Category: {module.category}")
        print(f"   📍 Path: {module.dotted_path}")
        print(f"   📝 Description: {module.description}")
        print(f"   ⚙️  Options: {list(module.opts.keys())}")
        
        # Show detailed options for first module
        if i == 1:
            print("   📋 Detailed options:")
            for opt_name, opt_info in module.opts.items():
                required = "✅" if opt_info.get("required") else "⚪"
                default = opt_info.get("default", "")
                desc = opt_info.get("description", "")
                print(f"      {required} {opt_name}: {desc} (default: '{default}')")
    
    print(f"\n🎯 Ready to launch GUI! Run: python main.py")
    print("   (Note: GUI requires a display - use VNC or local desktop)")
    
    print("\n✨ Features implemented:")
    features = [
        "🔍 Automatic RouterSploit module discovery",
        "🌳 Hierarchical module tree view",
        "⚙️  Dynamic option configuration",
        "🔄 Real-time output capture",
        "💾 Target history management",
        "🎨 Modern dark theme UI",
        "📊 Color-coded console output",
        "💥 Background thread execution",
        "🛡️  Error handling and validation"
    ]
    
    for feature in features:
        print(f"   {feature}")
    
    print(f"\n🚀 Total working modules: {len(modules_with_opts)}/{len(modules)}")


if __name__ == "__main__":
    main() 