"""Main entry point for RouterSploit GUI."""

import sys
from pathlib import Path

# Add the project root to the path for development
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from routersploit_gui.gui import main


def main_entry() -> None:
    """Main entry point for the application."""
    main()


if __name__ == "__main__":
    main_entry() 