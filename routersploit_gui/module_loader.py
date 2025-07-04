"""Module discovery and metadata extraction for RouterSploit."""

import importlib
import inspect
import pkgutil
import re
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
        cve_list: List of CVE numbers associated with the module
    """
    
    dotted_path: str
    cls: Type[Any]
    opts: Dict[str, Dict[str, Any]]
    category: str
    name: str
    description: str
    cve_list: List[str] = None

    def __post_init__(self):
        """Ensure cve_list is never None."""
        if self.cve_list is None:
            self.cve_list = []


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
            
            # Extract options using RouterSploit's option system
            options = self._extract_module_options(instance)
            
            # Generate name based on module path for better uniqueness
            # Clean up the dotted path (remove routersploit.modules prefix)
            clean_path = dotted_path.replace("routersploit.modules.", "")
            
            # Create descriptive names based on module path instead of class name
            path_parts = clean_path.split(".")
            
            if category == "payloads":
                # Extract meaningful name from the path
                # e.g., "payloads.armle.bind_tcp" -> "ARM LE Bind TCP"
                if len(path_parts) >= 3:  # payloads.arch.name
                    arch = path_parts[1].upper()  # armle -> ARMLE
                    payload_name = path_parts[2].replace("_", " ").title()  # bind_tcp -> Bind Tcp
                    name = f"{arch} {payload_name}"
                else:
                    # Fallback to path-based name
                    name = clean_path.split(".")[-1].replace("_", " ").title()
            elif category == "exploits":
                # For exploits, create names from the module path
                # e.g., "exploits.routers.dlink.dcs_930l_auth_rce" -> "DCS 930L Auth RCE"
                if len(path_parts) >= 3:
                    # Use the last part of the path as the exploit name
                    exploit_name = path_parts[-1].replace("_", " ").title()
                    name = exploit_name
                else:
                    name = clean_path.split(".")[-1].replace("_", " ").title()
            elif category == "scanners":
                # For scanners, use the module name
                # e.g., "scanners.autopwn" -> "Autopwn"
                name = path_parts[-1].replace("_", " ").title()
            elif category == "creds":
                # For creds modules, create descriptive names
                # e.g., "creds.routers.dlink.http_default_creds" -> "HTTP Default Creds"
                if len(path_parts) >= 3:
                    cred_name = path_parts[-1].replace("_", " ").title()
                    name = cred_name
                else:
                    name = path_parts[-1].replace("_", " ").title()
            else:
                # For other modules, use the last part of the path
                name = path_parts[-1].replace("_", " ").title()
            
            # Try multiple ways to get a meaningful description
            description = self._extract_description(instance, cls, name)
            
            # Extract CVE information
            cve_list = self._extract_cve_info(instance, cls)
            
            return ModuleMeta(
                dotted_path=clean_path,
                cls=cls,
                opts=options,
                category=category,
                name=name,
                description=description,
                cve_list=cve_list,
            )
            
        except Exception as e:
            logger.debug("Failed to extract metadata", cls=cls.__name__, error=str(e))
            return None
    
    def _extract_module_options(self, instance: Any) -> Dict[str, Dict[str, Any]]:
        """Extract options from a RouterSploit module instance.
        
        Args:
            instance: RouterSploit module instance
            
        Returns:
            Dictionary of options with metadata
        """
        options = {}
        module_name = instance.__class__.__name__
        
        try:
            # Method 1: Check for 'options' property (most common)
            if hasattr(instance, 'options'):
                option_names = instance.options
                for opt_name in option_names:
                    if hasattr(instance, opt_name):
                        opt_info = self._get_option_details(instance, opt_name)
                        if opt_info:
                            options[opt_name] = opt_info
            
            # Method 2: Check for '_get_advanced_info' method (some modules)
            if hasattr(instance, '_get_advanced_info'):
                try:
                    adv_info = instance._get_advanced_info()
                    if isinstance(adv_info, dict) and 'options' in adv_info:
                        for opt_name, opt_data in adv_info['options'].items():
                            if opt_name not in options:  # Don't override already found options
                                parsed_opt = self._parse_advanced_option(opt_name, opt_data)
                                if parsed_opt:
                                    options[opt_name] = parsed_opt
                except Exception as e:
                    logger.debug("Failed to extract advanced info", module=module_name, error=str(e))
            
            # Method 3: Inspect attributes directly (fallback)
            if not options:
                for attr_name in dir(instance):
                    if (not attr_name.startswith('_') and 
                        hasattr(instance, attr_name) and
                        attr_name not in ['run', 'options', 'check']):
                        
                        try:
                            attr_value = getattr(instance, attr_name)
                            if not callable(attr_value):
                                # This might be an option
                                opt_info = {
                                    "default": attr_value,
                                    "original_value": attr_value,
                                    "description": f"Module option: {attr_name}",
                                    "required": False,
                                    "type": type(attr_value).__name__
                                }
                                options[attr_name] = opt_info
                        except Exception:
                            continue
                            
        except Exception as e:
            logger.debug("Error extracting module options", module=module_name, error=str(e))
        
        # Enhance options with additional metadata detection
        for opt_name, opt_info in options.items():
            self._enhance_option_metadata(opt_name, opt_info, instance)
        
        logger.debug("Extracted options", module=module_name, count=len(options), options=list(options.keys()))
        return options
    
    def _get_option_details(self, instance: Any, opt_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific option.
        
        Args:
            instance: RouterSploit module instance
            opt_name: Name of the option
            
        Returns:
            Dictionary with option details or None if invalid
        """
        try:
            # Get the current value
            current_value = getattr(instance, opt_name, None)
            
            # Determine if this is required
            required = self._is_required_option(opt_name, instance)
            
            # Get description
            description = self._get_option_description(opt_name, instance)
            
            # Extract constraints and option type
            constraints = self._extract_option_constraints(opt_name, instance, current_value)
            
            # Use constraint option_type if available, otherwise determine from value
            option_type = constraints.get("option_type") or self._determine_option_type_from_value(current_value)
            
            option_info = {
                "default": current_value,
                "original_value": current_value,
                "current_value": current_value,
                "description": description,
                "required": required,
                "option_type": option_type,
                **constraints  # Add any additional constraints (choices, min/max, etc.)
            }
            
            return option_info
            
        except Exception as e:
            logger.debug("Failed to get option details", option=opt_name, error=str(e))
            return None
    
    def _determine_option_type_from_value(self, value: Any) -> str:
        """Determine option type from its value.
        
        Args:
            value: The option value
            
        Returns:
            String indicating the option type
        """
        if value is None:
            return "text"
        elif isinstance(value, bool):
            return "boolean"
        elif isinstance(value, int):
            return "integer"
        elif isinstance(value, float):
            return "float"
        elif isinstance(value, (list, tuple)):
            return "list"
        elif isinstance(value, dict):
            return "dict"
        else:
            return "text"
    
    def _extract_option_constraints(self, opt_name: str, instance: Any, current_value: Any) -> Dict[str, Any]:
        """Extract additional constraints for an option.
        
        Args:
            opt_name: Option name
            instance: Module instance
            current_value: Current option value
            
        Returns:
            Dictionary of constraints
        """
        constraints = {}
        
        try:
            # Check for choice-based options by looking for validation methods
            validate_method_name = f"validate_{opt_name}"
            if hasattr(instance, validate_method_name):
                try:
                    validate_method = getattr(instance, validate_method_name)
                    if callable(validate_method):
                        # Try to infer choices from validation method (limited capability)
                        constraints["has_validator"] = True
                except Exception:
                    pass
            
            # Special handling for encoder options
            if opt_name.lower() == "encoder" and hasattr(instance, '__module__'):
                encoder_choices = self._get_encoder_choices()
                if encoder_choices:
                    constraints["choices"] = encoder_choices
                    constraints["type_hint"] = "choice"
            
            # Special handling for output format options
            if opt_name.lower() == "output" and hasattr(instance, '__module__'):
                if "payload" in str(instance.__module__):
                    output_choices = ["python", "perl", "bash", "raw", "c", "javascript"]
                    constraints["choices"] = output_choices
                    constraints["type_hint"] = "choice"
            
            # Check for boolean options by current value or name pattern
            if isinstance(current_value, bool) or any(term in opt_name.lower() for term in ["enable", "disable", "ssl", "https", "verify", "use"]):
                constraints["option_type"] = "boolean"
            
            # Check for port-related options
            elif "port" in opt_name.lower() and (isinstance(current_value, int) or str(current_value).isdigit()):
                constraints["min_value"] = 1
                constraints["max_value"] = 65535
                constraints["option_type"] = "port"
            
            # Check for file/path options
            elif any(term in opt_name.lower() for term in ["file", "path", "cert", "key"]):
                constraints["option_type"] = "file"
            
            # Check for IP/hostname options
            elif any(term in opt_name.lower() for term in ["host", "target", "ip", "rhost", "lhost"]):
                constraints["option_type"] = "text"
                constraints["type_hint"] = "hostname"
            
            # Check for numeric options
            elif isinstance(current_value, int) or (isinstance(current_value, str) and current_value.isdigit()):
                constraints["option_type"] = "integer"
                
        except Exception as e:
            logger.debug("Error extracting constraints", option=opt_name, error=str(e))
        
        return constraints
    
    def _get_encoder_choices(self) -> List[str]:
        """Get available encoder choices for payloads.
        
        Returns:
            List of available encoder names
        """
        try:
            # Try to import RouterSploit encoders
            import routersploit.modules.encoders
            import pkgutil
            
            encoders = [""]  # Start with empty option (no encoder)
            
            # Walk through encoder modules
            for importer, modname, ispkg in pkgutil.walk_packages(
                routersploit.modules.encoders.__path__, 
                prefix="routersploit.modules.encoders."
            ):
                if not ispkg:
                    try:
                        # Extract encoder name from module path
                        encoder_name = modname.split(".")[-1]
                        if not encoder_name.startswith("_"):
                            encoders.append(encoder_name)
                    except Exception:
                        continue
            
            # Remove duplicates and sort
            unique_encoders = list(dict.fromkeys(encoders))  # Preserves order
            return sorted(unique_encoders)
        except Exception as e:
            logger.debug("Failed to get encoder choices", error=str(e))
            # Return common encoder choices as fallback (without duplicates)
            return ["", "base64", "hex", "url", "none"]
    
    def _enhance_option_metadata(self, opt_name: str, opt_info: Dict[str, Any], instance: Any) -> None:
        """Enhance option metadata with additional information.
        
        Args:
            opt_name: Option name
            opt_info: Current option info to enhance
            instance: Module instance
        """
        try:
            # Enhanced description based on option name patterns
            if opt_info.get("description") == f"Module option: {opt_name}":
                enhanced_desc = self._generate_enhanced_description(opt_name, opt_info)
                opt_info["description"] = enhanced_desc
            
            # Add GUI hints
            opt_info["gui_hints"] = self._generate_gui_hints(opt_name, opt_info)
            
            # Add validation hints
            opt_info["validation_hints"] = self._generate_validation_hints(opt_name, opt_info)
            
        except Exception as e:
            logger.debug("Error enhancing option metadata", option=opt_name, error=str(e))
    
    def _generate_enhanced_description(self, opt_name: str, opt_info: Dict[str, Any]) -> str:
        """Generate an enhanced description for an option.
        
        Args:
            opt_name: Option name
            opt_info: Option information
            
        Returns:
            Enhanced description string
        """
        base_name = opt_name.lower()
        
        # Common option descriptions
        descriptions = {
            "target": "Target hostname or IP address",
            "rhost": "Remote host to target",
            "lhost": "Local host for connections",
            "rport": "Remote port number",
            "lport": "Local port number",
            "port": "Port number to target",
            "username": "Username for authentication",
            "password": "Password for authentication",
            "payload": "Payload to execute",
            "threads": "Number of concurrent threads",
            "timeout": "Connection timeout in seconds",
            "ssl": "Use SSL/TLS encryption",
            "verify": "Verify SSL certificates",
            "verbose": "Enable verbose output",
            "file": "File path",
            "output": "Output file path",
            "wordlist": "Wordlist file path"
        }
        
        # Check for exact matches
        if base_name in descriptions:
            return descriptions[base_name]
        
        # Check for partial matches
        for key, desc in descriptions.items():
            if key in base_name:
                return desc
                
        # Generate based on type
        option_type = opt_info.get("type", "text")
        if option_type == "boolean":
            return f"Enable or disable {opt_name.replace('_', ' ')}"
        elif option_type == "integer":
            return f"Numeric value for {opt_name.replace('_', ' ')}"
        elif "port" in base_name:
            return f"Port number for {opt_name.replace('_', ' ')}"
        elif "file" in base_name or "path" in base_name:
            return f"File path for {opt_name.replace('_', ' ')}"
        else:
            return f"Configuration value for {opt_name.replace('_', ' ')}"
    
    def _generate_gui_hints(self, opt_name: str, opt_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate GUI hints for better input control selection.
        
        Args:
            opt_name: Option name
            opt_info: Option information
            
        Returns:
            Dictionary of GUI hints
        """
        hints = {}
        base_name = opt_name.lower()
        option_type = opt_info.get("type", "text")
        
        # Input control type hints
        if option_type == "boolean":
            hints["control_type"] = "dropdown"
            hints["choices"] = ["true", "false"]
        elif "port" in base_name or opt_info.get("type_hint") == "port":
            hints["control_type"] = "number"
            hints["min_value"] = 1
            hints["max_value"] = 65535
        elif "file" in base_name or "path" in base_name or opt_info.get("type_hint") == "file":
            hints["control_type"] = "file_browser"
        elif base_name in ["target", "rhost", "lhost", "host", "hostname"]:
            hints["control_type"] = "text"
            hints["placeholder"] = "hostname or IP address"
        elif option_type == "integer":
            hints["control_type"] = "number"
        else:
            hints["control_type"] = "text"
            
        # Size hints
        if base_name in ["target", "rhost", "lhost", "host"]:
            hints["size"] = (25, 1)
        elif "port" in base_name:
            hints["size"] = (10, 1)
        elif option_type == "boolean":
            hints["size"] = (10, 1)
        else:
            hints["size"] = (30, 1)
            
        return hints
    
    def _generate_validation_hints(self, opt_name: str, opt_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate validation hints for input validation.
        
        Args:
            opt_name: Option name
            opt_info: Option information
            
        Returns:
            Dictionary of validation hints
        """
        hints = {}
        base_name = opt_name.lower()
        option_type = opt_info.get("type", "text")
        
        # Required field detection
        if base_name in ["target", "rhost", "host"]:
            hints["likely_required"] = True
        
        # Pattern validation
        if base_name in ["target", "rhost", "lhost", "host", "hostname"]:
            hints["pattern_type"] = "hostname_or_ip"
        elif "port" in base_name:
            hints["pattern_type"] = "port_number"
            hints["min_value"] = 1
            hints["max_value"] = 65535
        elif "email" in base_name:
            hints["pattern_type"] = "email"
        elif "url" in base_name:
            hints["pattern_type"] = "url"
            
        # Value constraints
        if option_type == "integer":
            if "threads" in base_name:
                hints["min_value"] = 1
                hints["max_value"] = 100
            elif "timeout" in base_name:
                hints["min_value"] = 1
                hints["max_value"] = 300
                
        return hints
    
    def _is_required_option(self, opt_name: str, instance: Any) -> bool:
        """Determine if an option is required.
        
        Args:
            opt_name: Option name
            instance: Module instance
            
        Returns:
            True if option is required
        """
        # Common required options
        required_patterns = ['target', 'rhost', 'host']
        
        # Check if this option matches required patterns
        if opt_name.lower() in required_patterns:
            return True
        
        # Check for required_options attribute
        if hasattr(instance, 'required_options'):
            required_opts = getattr(instance, 'required_options', [])
            if opt_name in required_opts:
                return True
        
        # Check for _required_options attribute
        if hasattr(instance, '_required_options'):
            required_opts = getattr(instance, '_required_options', [])
            if opt_name in required_opts:
                return True
        
        return False
    
    def _get_option_description(self, opt_name: str, instance: Any) -> str:
        """Get description for an option.
        
        Args:
            opt_name: Option name
            instance: Module instance
            
        Returns:
            Option description
        """
        # Check for description attribute
        desc_attr = f"{opt_name}_description"
        if hasattr(instance, desc_attr):
            desc = getattr(instance, desc_attr)
            if isinstance(desc, str):
                return desc
        
        # Check for info attribute
        info_attr = f"{opt_name}_info"
        if hasattr(instance, info_attr):
            info = getattr(instance, info_attr)
            if isinstance(info, str):
                return info
        
        # Use predefined descriptions for common options
        descriptions = {
            "target": "Target IP address or hostname",
            "rhost": "Remote host IP address",
            "rport": "Remote host port number", 
            "port": "Target port number",
            "ssl": "Use SSL/TLS connection",
            "verbosity": "Enable verbose output",
            "threads": "Number of threads to use",
            "timeout": "Connection timeout in seconds",
            "username": "Username for authentication",
            "password": "Password for authentication",
            "payload": "Payload to execute",
            "lhost": "Local host IP address",
            "lport": "Local port number",
            "arch": "Target architecture",
            "platform": "Target platform",
            "filepath": "Path to file",
            "filename": "Name of file",
        }
        
        return descriptions.get(opt_name.lower(), f"Option: {opt_name}")
    
    def _parse_advanced_option(self, opt_name: str, opt_data: Any) -> Optional[Dict[str, Any]]:
        """Parse option data from advanced info.
        
        Args:
            opt_name: Option name
            opt_data: Option data from advanced info
            
        Returns:
            Parsed option details or None
        """
        try:
            if isinstance(opt_data, dict):
                default = opt_data.get('default', '')
                description = opt_data.get('description', f"Option: {opt_name}")
                required = opt_data.get('required', False)
                
                return {
                    "default": self._format_option_value(default),
                    "original_value": default,
                    "description": description,
                    "required": required,
                    "type": type(default).__name__ if default is not None else "str",
                }
        except Exception:
            pass
        
        return None
    
    def _extract_description(self, instance: Any, cls: Type[Any], name: str) -> str:
        """Extract a meaningful description for the module.
        
        Args:
            instance: Module instance
            cls: Module class
            name: Module name
            
        Returns:
            Description string
        """
        description = ""
        
        # Try multiple sources for description
        sources = [
            # 1. Check for a 'description' attribute
            lambda: getattr(instance, 'description', None),
            # 2. Check for an 'info' attribute (common in RouterSploit)
            lambda: getattr(instance, 'info', None),
            # 3. Check class docstring
            lambda: cls.__doc__.strip() if cls.__doc__ else None,
            # 4. Check instance docstring
            lambda: instance.__doc__.strip() if hasattr(instance, '__doc__') and instance.__doc__ else None,
            # 5. Look for reference attributes
            lambda: getattr(instance, 'reference', None),
            # 6. Look for author information
            lambda: f"Module by {getattr(instance, 'author', 'Unknown')}" if hasattr(instance, 'author') else None,
        ]
        
        for source in sources:
            try:
                result = source()
                if result and isinstance(result, str) and result.strip():
                    description = result.strip()
                    break
            except Exception:
                continue
        
        # If still no description, create one from the module path/name
        if not description:
            # Get the module path for better context
            module_path = cls.__module__.replace("routersploit.modules.", "")
            path_parts = module_path.split(".")
            
            # Extract vendor/device info for better descriptions
            vendor = ""
            device_type = ""
            
            if len(path_parts) >= 3:
                if path_parts[0] == "exploits":
                    device_type = path_parts[1]  # routers, cameras, etc.
                    vendor = path_parts[2].title()  # dlink, netgear, etc.
                elif path_parts[0] == "creds":
                    device_type = path_parts[1]  # routers, cameras, etc.
                    vendor = path_parts[2].title() if len(path_parts) > 2 else ""
            
            # Create description based on module name and category patterns
            name_lower = name.lower()
            if "rce" in name_lower:
                if vendor:
                    description = f"Remote Code Execution exploit targeting {vendor} {device_type}"
                else:
                    description = f"Remote Code Execution exploit"
            elif "sqli" in name_lower or "sql" in name_lower:
                if vendor:
                    description = f"SQL Injection exploit targeting {vendor} {device_type}"
                else:
                    description = f"SQL Injection exploit"
            elif "auth" in name_lower and "bypass" in name_lower:
                if vendor:
                    description = f"Authentication bypass exploit for {vendor} {device_type}"
                else:
                    description = f"Authentication bypass exploit"
            elif "disclosure" in name_lower or "leak" in name_lower:
                if vendor:
                    description = f"Information disclosure exploit for {vendor} {device_type}"
                else:
                    description = f"Information disclosure exploit"
            elif "path_traversal" in name_lower or "traversal" in name_lower:
                if vendor:
                    description = f"Path traversal exploit for {vendor} {device_type}"
                else:
                    description = f"Path traversal exploit"
            elif "dos" in name_lower or "denial" in name_lower:
                if vendor:
                    description = f"Denial of Service exploit for {vendor} {device_type}"
                else:
                    description = f"Denial of Service exploit"
            elif "command" in name_lower and "inject" in name_lower:
                if vendor:
                    description = f"Command injection exploit for {vendor} {device_type}"
                else:
                    description = f"Command injection exploit"
            elif "default" in name_lower and "creds" in name_lower:
                if vendor:
                    description = f"Default credentials check for {vendor} {device_type}"
                else:
                    description = f"Default credentials check"
            elif "scanner" in cls.__module__ or path_parts[0] == "scanners":
                if "autopwn" in name_lower:
                    description = f"Automated exploitation scanner"
                else:
                    description = f"Network security scanner: {name}"
            elif "payload" in cls.__module__ or path_parts[0] == "payloads":
                description = f"Payload module: {name}"
            elif "encoder" in cls.__module__ or path_parts[0] == "encoders":
                description = f"Payload encoder: {name}"
            else:
                if vendor and device_type:
                    description = f"Security testing module for {vendor} {device_type}"
                else:
                    description = f"Security testing module"
        
        # Clean up the description
        description = self._clean_description(description)
        
        # Limit length
        if len(description) > 120:
            description = description[:117] + "..."
            
        return description
    
    def _extract_cve_info(self, instance: Any, cls: Type[Any]) -> List[str]:
        """Extract CVE information from a RouterSploit module.
        
        Args:
            instance: Module instance
            cls: Module class
            
        Returns:
            List of CVE numbers found in the module
        """
        cve_list = []
        
        # CVE pattern matching (CVE-YEAR-NUMBER format)
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
        
        try:
            # Method 1: Check for __info__ attribute (most common in RouterSploit)
            if hasattr(cls, '__info__') and isinstance(cls.__info__, dict):
                info = cls.__info__
                
                # Check references section
                if 'references' in info:
                    references = info['references']
                    if isinstance(references, (list, tuple)):
                        for ref in references:
                            if isinstance(ref, str):
                                cves = cve_pattern.findall(ref)
                                cve_list.extend(cves)
                
                # Check description for CVE mentions
                if 'description' in info and isinstance(info['description'], str):
                    cves = cve_pattern.findall(info['description'])
                    cve_list.extend(cves)
                
                # Check name for CVE mentions
                if 'name' in info and isinstance(info['name'], str):
                    cves = cve_pattern.findall(info['name'])
                    cve_list.extend(cves)
            
            # Method 2: Check instance attributes
            if hasattr(instance, '__info__') and isinstance(instance.__info__, dict):
                info = instance.__info__
                
                if 'references' in info:
                    references = info['references']
                    if isinstance(references, (list, tuple)):
                        for ref in references:
                            if isinstance(ref, str):
                                cves = cve_pattern.findall(ref)
                                cve_list.extend(cves)
            
            # Method 3: Check docstring
            if cls.__doc__:
                cves = cve_pattern.findall(cls.__doc__)
                cve_list.extend(cves)
            
            # Method 4: Check module path for CVE hints (like netgear module with 2017-5521)
            module_path = cls.__module__ if hasattr(cls, '__module__') else ""
            if module_path:
                cves = cve_pattern.findall(module_path)
                cve_list.extend(cves)
                
                # Also check if there are year-number patterns that might be CVEs
                year_pattern = re.compile(r'-(\d{4})-(\d{4,})', re.IGNORECASE)
                year_matches = year_pattern.findall(module_path)
                for year, number in year_matches:
                    # If it looks like a CVE format, add it
                    if int(year) >= 1999 and int(year) <= 2030:  # Reasonable CVE year range
                        cve_candidate = f"CVE-{year}-{number}"
                        if cve_candidate not in cve_list:
                            cve_list.append(cve_candidate)
            
            # Remove duplicates and normalize case
            unique_cves = []
            for cve in cve_list:
                cve_normalized = cve.upper()
                if cve_normalized not in unique_cves:
                    unique_cves.append(cve_normalized)
            
            # Sort CVEs for consistent output
            unique_cves.sort()
            
            if unique_cves:
                logger.debug("Found CVEs for module", module=cls.__name__, cves=unique_cves)
            
            return unique_cves
            
        except Exception as e:
            logger.debug("Failed to extract CVE info", module=cls.__name__, error=str(e))
            return []
    
    def _clean_description(self, description: str) -> str:
        """Clean and format a description string.
        
        Args:
            description: Raw description string
            
        Returns:
            Cleaned description
        """
        if not description:
            return ""
            
        # Remove extra whitespace and newlines
        description = " ".join(description.split())
        
        # Remove common prefixes that don't add value
        prefixes_to_remove = [
            "Module ",
            "Exploit ",
            "Scanner ",
            "This module ",
            "This exploit ",
            "This scanner ",
        ]
        
        for prefix in prefixes_to_remove:
            if description.startswith(prefix):
                description = description[len(prefix):]
                break
        
        # Capitalize first letter
        if description:
            description = description[0].upper() + description[1:]
            
        return description
    
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