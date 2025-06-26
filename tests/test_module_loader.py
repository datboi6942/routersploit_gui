"""Tests for module loader."""

import pytest
from unittest.mock import Mock, patch

from routersploit_gui.module_loader import ModuleLoader, ModuleMeta


def test_module_meta_dataclass() -> None:
    """Test ModuleMeta dataclass creation."""
    meta = ModuleMeta(
        dotted_path="test.module",
        cls=Mock,
        opts={"target": {"default": "127.0.0.1"}},
        category="exploits",
        name="Test Module",
        description="A test module",
    )
    
    assert meta.dotted_path == "test.module"
    assert meta.cls == Mock
    assert meta.opts == {"target": {"default": "127.0.0.1"}}
    assert meta.category == "exploits"
    assert meta.name == "Test Module"
    assert meta.description == "A test module"


def test_module_loader_init() -> None:
    """Test ModuleLoader initialization."""
    loader = ModuleLoader()
    assert loader._modules == []
    assert loader._tree == {}


@patch('routersploit_gui.module_loader.importlib')
def test_discover_modules_no_routersploit(mock_importlib: Mock) -> None:
    """Test module discovery when RouterSploit is not available."""
    mock_importlib.import_module.side_effect = ImportError("No module named 'routersploit'")
    
    loader = ModuleLoader()
    
    with pytest.raises(ImportError, match="RouterSploit not installed"):
        loader.discover_modules()


def test_discover_modules_success() -> None:
    """Test successful module discovery."""
    loader = ModuleLoader()
    modules = loader.discover_modules()
    
    # Should find modules
    assert len(modules) > 0
    
    # All should be ModuleMeta instances
    assert all(isinstance(m, ModuleMeta) for m in modules)
    
    # Should have various categories
    categories = {m.category for m in modules}
    assert len(categories) > 0


def test_build_tree_with_modules() -> None:
    """Test building tree with discovered modules."""
    loader = ModuleLoader()
    tree = loader.build_tree()
    
    # Should have categories
    assert len(tree) > 0
    assert isinstance(tree, dict)


def test_get_modules_empty() -> None:
    """Test getting modules when none are loaded."""
    loader = ModuleLoader()
    modules = loader.get_modules()
    assert modules == []


def test_get_tree_empty() -> None:
    """Test getting tree when empty."""
    loader = ModuleLoader()
    tree = loader.get_tree()
    assert tree == {} 