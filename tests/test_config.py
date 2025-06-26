"""Tests for configuration module."""

from pathlib import Path

from routersploit_gui import config


def test_config_constants() -> None:
    """Test that all required configuration constants are defined."""
    assert config.APP_NAME == "RouterSploit GUI"
    assert config.APP_VERSION == "0.1.0"
    assert config.WINDOW_SIZE == (1200, 800)
    assert config.UPDATE_INTERVAL_MS == 50
    

def test_config_paths() -> None:
    """Test that configuration paths are properly set."""
    assert isinstance(config.CONFIG_DIR, Path)
    assert isinstance(config.HISTORY_FILE, Path)
    assert isinstance(config.ASSETS_DIR, Path)
    
    # Config directory should be created
    assert config.CONFIG_DIR.exists()
    

def test_config_colors() -> None:
    """Test that color constants are valid hex colors."""
    colors = [
        config.SUCCESS_COLOR,
        config.ERROR_COLOR,
        config.WARNING_COLOR,
        config.INFO_COLOR,
    ]
    
    for color in colors:
        assert color.startswith("#")
        assert len(color) == 7
        # Check it's valid hex
        int(color[1:], 16) 