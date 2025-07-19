"""Configuration settings for RouterSploit GUI."""

import os
from pathlib import Path
from typing import Final

# Application settings
APP_NAME: Final[str] = "RouterSploit GUI"
APP_VERSION: Final[str] = "0.1.0"

# Environment and logging
ENVIRONMENT: Final[str] = os.getenv("RSF_GUI_ENV", "production")
LOG_LEVEL: Final[int] = 10  # DEBUG level for troubleshooting

# GUI settings
WINDOW_SIZE: Final[tuple[int, int]] = (1200, 800)
TREE_WIDTH: Final[int] = 300
CONSOLE_HEIGHT: Final[int] = 200
UPDATE_INTERVAL_MS: Final[int] = 50

# Paths
CONFIG_DIR: Final[Path] = Path.home() / ".config" / "rsf_gui"
HISTORY_FILE: Final[Path] = CONFIG_DIR / "history.json"
ASSETS_DIR: Final[Path] = Path(__file__).parent / "assets"

# RouterSploit discovery
RSF_MODULE_PATTERNS: Final[list[str]] = [
    "routersploit.modules.exploits.*",
    "routersploit.modules.scanners.*",
    "routersploit.modules.creds.*",
    "routersploit.modules.payloads.*",
]

# LLM and Auto-Own Configuration
# OPENAI_API_KEY is now set at runtime, not at startup
OPENAI_MODEL: Final[str] = os.getenv("OPENAI_MODEL", "gpt-4")
OPENAI_MAX_TOKENS: Final[int] = 4000
OPENAI_TEMPERATURE: Final[float] = 0.1

OPENAI_API_KEY_FILE: Final[Path] = CONFIG_DIR / "openai_api_key.txt"

def get_openai_api_key() -> str:
    """Get the OpenAI API key from the config file, or return empty string if not set."""
    try:
        if OPENAI_API_KEY_FILE.exists():
            return OPENAI_API_KEY_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        pass
    return ""

def set_openai_api_key(key: str) -> None:
    """Set the OpenAI API key in the config file."""
    OPENAI_API_KEY_FILE.write_text(key.strip(), encoding="utf-8")

# ExploitDB Configuration
EXPLOITDB_API_KEY_FILE: Final[Path] = CONFIG_DIR / "exploitdb_api_key.txt"

def get_exploitdb_api_key() -> str:
    """Get the ExploitDB API key from the config file, or return empty string if not set."""
    try:
        if EXPLOITDB_API_KEY_FILE.exists():
            return EXPLOITDB_API_KEY_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        pass
    return ""

def set_exploitdb_api_key(key: str) -> None:
    """Set the ExploitDB API key in the config file."""
    # Ensure config directory exists
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    EXPLOITDB_API_KEY_FILE.write_text(key.strip(), encoding="utf-8")

# Tool Configuration
NMAP_PATH: Final[str] = os.getenv("NMAP_PATH", "/usr/bin/nmap")
METASPLOIT_PATH: Final[str] = os.getenv("MSF_PATH", "/usr/bin/msfconsole")
EXPLOIT_DB_API_KEY: Final[str] = os.getenv("EXPLOIT_DB_API_KEY", "")

# Security Settings
AUTO_OWN_ENABLED: Final[bool] = True  # Always enabled by default
SANDBOX_EXECUTION: Final[bool] = os.getenv("SANDBOX_EXECUTION", "true").lower() == "true"
MAX_EXECUTION_TIME: Final[int] = int(os.getenv("MAX_EXECUTION_TIME", "300"))  # 5 minutes
REQUIRE_USER_APPROVAL: Final[bool] = os.getenv("REQUIRE_USER_APPROVAL", "true").lower() == "true"

# Auto-Own Logging
AUTO_OWN_LOG_FILE: Final[Path] = CONFIG_DIR / "auto_own.log"
AUTO_OWN_RESULTS_DIR: Final[Path] = CONFIG_DIR / "auto_own_results"

# Styling
THEME: Final[str] = "DarkBlue3"

# Available themes for customization
AVAILABLE_THEMES: Final[list[str]] = [
    "DarkBlue3",
    "DarkGrey",
    "Dark",
    "DarkAmber",
    "DarkBrown",
    "DarkGreen",
    "DarkPurple",
    "DarkRed",
    "DarkTeal",
    "LightBlue",
    "LightGreen",
    "LightGrey",
    "Default1",
    "DefaultNoMoreNagging",
    "Material1",
    "Material2",
    "Reddit",
    "Topanga",
    "GreenTan",
    "BrownBlue",
    "BrightColors",
    "NeutralBlue",
    "Kay",
    "TanBlue",
]

# Theme configuration file
THEME_CONFIG_FILE: Final[Path] = CONFIG_DIR / "theme.json"

SUCCESS_COLOR: Final[str] = "#4CAF50"
ERROR_COLOR: Final[str] = "#F44336"
WARNING_COLOR: Final[str] = "#FF9800"
INFO_COLOR: Final[str] = "#2196F3"
PRIMARY_COLOR: Final[str] = "#1976D2"
SECONDARY_COLOR: Final[str] = "#424242"
ACCENT_COLOR: Final[str] = "#FF4081"

# Modern GUI styling
FONT_MAIN: Final[tuple[str, int]] = ("Segoe UI", 10)
FONT_HEADING: Final[tuple[str, int, str]] = ("Segoe UI", 12, "bold")
FONT_MONO: Final[tuple[str, int]] = ("Consolas", 9)
BUTTON_SIZE: Final[tuple[int, int]] = (12, 1)
INPUT_SIZE: Final[tuple[int, int]] = (30, 1)

# Ensure config directory exists
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
AUTO_OWN_RESULTS_DIR.mkdir(parents=True, exist_ok=True) 