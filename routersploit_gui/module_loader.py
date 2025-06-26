"""Module discovery and metadata extraction for RouterSploit."""

import importlib
import inspect
import pkgutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ModuleMeta:
    """Metadata for a RouterSploit module.
    
    Args:
        dotted_path: The Python module path (e.g., 'exploits.routers.netgear.multi_rce')
        cls: The exploit class reference
        opts: Dictionary of option_name -> option_info
        category: Module category (exploits, scanners, etc.)
        name: Human-readable name
        description: Module description
    """
    
    dotted_path: str
    cls: Type[Any]
    opts: Dict[str, Dict[str, Any]]
    category: str
    name: str
    description: str


class ModuleLoader:
    """Discovers and loads RouterSploit modules."""
    
    def __init__(self) -> None:
        """Initialize the module loader."""
        self._modules: List[ModuleMeta] = []
        self._tree: Dict[str, Any] = {}
    
    def discover_modules(self) -> List[ModuleMeta]:
        """Discover all available RouterSploit modules.
        
        Returns:
            List of module metadata objects
            
        Raises:
            ImportError: If RouterSploit cannot be imported
            RuntimeError: If no modules are found
        """
        try:
            import routersploit.modules
        except ImportError as e:
            logger.error("RouterSploit not found", error=str(e))
            raise ImportError(
                "RouterSploit not installed. Install with: pip install routersploit"
            ) from e
        
        self._modules = []
        rsf_path = Path(routersploit.modules.__file__).parent
        
        for category_dir in rsf_path.iterdir():
            if not category_dir.is_dir() or category_dir.name.startswith("_"):
                continue
                
            category = category_dir.name
            self._discover_category(category, category_dir)
        
        if not self._modules:
            raise RuntimeError("No RouterSploit modules found")
            
        logger.info("Discovered modules", count=len(self._modules))
        return self._modules
    
    def _discover_category(self, category: str, category_path: Path) -> None:
        """Discover modules in a specific category.
        
        Args:
            category: The category name (exploits, scanners, etc.)
            category_path: Path to the category directory
        """
        module_prefix = f"routersploit.modules.{category}"
        
        try:
            category_module = importlib.import_module(module_prefix)
        except ImportError:
            logger.warning("Failed to import category", category=category)
            return
            
        for importer, modname, ispkg in pkgutil.walk_packages(
            category_module.__path__, prefix=f"{module_prefix}."
        ):
            if ispkg:
                continue
                
            try:
                module = importlib.import_module(modname)
                exploit_class = self._find_exploit_class(module)
                
                if exploit_class:
                    meta = self._extract_metadata(modname, exploit_class, category)
                    if meta:
                        self._modules.append(meta)
                        
            except Exception as e:
                logger.debug("Skipping module", module=modname, error=str(e))
    
    def _find_exploit_class(self, module: Any) -> Optional[Type[Any]]:
        """Find the main exploit class in a module.
        
        Args:
            module: The imported module
            
        Returns:
            The exploit class if found, None otherwise
        """
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                obj.__module__ == module.__name__  # Local to this module
                and hasattr(obj, "options")  # Has options property
                and hasattr(obj, "run")  # Has run method
                and not name.startswith("_")
            ):
                return obj
        return None
    
    def _extract_metadata(
        self, dotted_path: str, cls: Type[Any], category: str
    ) -> Optional[ModuleMeta]:
        """Extract metadata from an exploit class.
        
        Args:
            dotted_path: The module's dotted path
            cls: The exploit class
            category: The module category
            
        Returns:
            ModuleMeta object if valid, None otherwise
        """
        try:
            # Create an instance to access options
            instance = cls()
            
            # Get options - RouterSploit modules have an options property
            if hasattr(instance, 'options'):
                option_names = instance.options
            else:
                option_names = []
            
            # Build options dictionary
            options = {}
            for opt_name in option_names:
                if hasattr(instance, opt_name):
                    opt_value = getattr(instance, opt_name)
                    
                    # Determine if required (target is usually required)
                    required = opt_name.lower() in ["target", "rhost"]
                    
                    # Create description
                    description = {
                        "target": "Target IP address or hostname",
                        "port": "Target port number",
                        "ssl": "Use SSL/TLS connection",
                        "verbosity": "Enable verbose output",
                        "rhost": "Remote host IP address",
                        "rport": "Remote host port number",
                    }.get(opt_name.lower(), f"Option {opt_name}")
                    
                    options[opt_name] = {
                        "default": str(opt_value) if opt_value is not None else "",
                        "description": description,
                        "required": required,
                    }
            
            # Generate name and description
            class_name = cls.__name__
            name = class_name.replace("_", " ").title()
            
            # Try to get description from docstring
            description = cls.__doc__.strip() if cls.__doc__ else f"{name} module"
            if len(description) > 100:
                description = description[:97] + "..."
            
            # Clean up the dotted path (remove routersploit.modules prefix)
            clean_path = dotted_path.replace("routersploit.modules.", "")
            
            return ModuleMeta(
                dotted_path=clean_path,
                cls=cls,
                opts=options,
                category=category,
                name=name,
                description=description,
            )
            
        except Exception as e:
            logger.debug("Failed to extract metadata", cls=cls.__name__, error=str(e))
            return None
    
    def build_tree(self) -> Dict[str, Any]:
        """Build a hierarchical tree structure from discovered modules.
        
        Returns:
            Nested dictionary representing the module tree
        """
        if not self._modules:
            self.discover_modules()
            
        self._tree = {}
        
        for meta in self._modules:
            parts = meta.dotted_path.split(".")
            current = self._tree
            
            # Navigate/create the tree structure
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            
            # Add the final module
            current[parts[-1]] = meta
            
        return self._tree
    
    def get_module_by_key(self, key: str) -> Optional[ModuleMeta]:
        """Get module metadata by its tree key.

        Args:
            key: The key from the tree (e.g., 'exploits/routers/dlink/dns_320l_rce')

        Returns:
            ModuleMeta if found, else None.
        """
        if not self._tree:
            self.build_tree()

        parts = key.split("/")
        current = self._tree
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None  # Not found

        if isinstance(current, ModuleMeta):
            return current
        return None
    
    def get_modules(self) -> List[ModuleMeta]:
        """Get all discovered modules.
        
        Returns:
            List of all module metadata
        """
        return self._modules
    
    def get_tree(self) -> Dict[str, Any]:
        """Get the module tree.
        
        Returns:
            The hierarchical module tree
        """
        return self._tree 