"""Console interface for RouterSploit GUI.

This module provides a command-line interface compatible with RouterSploit
for both general use and post-exploitation session handling.
"""

import asyncio
import queue
import re
import shlex
import threading
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import contextlib
import io
import sys

import structlog

from .module_loader import ModuleLoader, ModuleMeta

logger = structlog.get_logger(__name__)


class RouterSploitSession:
    """Represents an active RouterSploit session (post-exploitation)."""
    
    def __init__(self, session_id: str, module_instance: Any):
        """Initialize a RouterSploit session.
        
        Args:
            session_id: Unique identifier for the session
            module_instance: The exploit module instance with an active session
        """
        self.session_id = session_id
        self.module_instance = module_instance
        self.is_active = True
        self.command_history: List[str] = []
        
    def execute_command(self, command: str) -> Tuple[bool, str]:
        """Execute a command in the session.
        
        Args:
            command: Command to execute
            
        Returns:
            Tuple of (success, output)
        """
        try:
            if hasattr(self.module_instance, 'session') and self.module_instance.session:
                # Try to execute command in the session
                result = self.module_instance.session.exec_command(command)
                self.command_history.append(command)
                return True, result
            else:
                return False, "No active session available"
        except Exception as e:
            return False, f"Command execution failed: {str(e)}"
    
    def close(self) -> None:
        """Close the session."""
        self.is_active = False
        if hasattr(self.module_instance, 'session') and self.module_instance.session:
            try:
                self.module_instance.session.close()
            except Exception as e:
                logger.warning("Error closing session", error=str(e))


class ConsoleHandler:
    """Handles RouterSploit console commands and sessions."""
    
    def __init__(self, module_loader: ModuleLoader):
        """Initialize the console handler.
        
        Args:
            module_loader: Module loader instance for accessing RouterSploit modules
        """
        self.module_loader = module_loader
        self.modules: Dict[str, ModuleMeta] = {}
        self.current_module: Optional[ModuleMeta] = None
        self.current_module_instance: Optional[Any] = None
        self.sessions: Dict[str, RouterSploitSession] = {}
        self.active_session: Optional[str] = None
        self.command_history: List[str] = []
        self.workspace = "default"
        
        # Load modules
        self._load_modules()
        
        # Console state
        self.prompt = "rsf > "
        self.output_callback: Optional[Callable[[str, str], None]] = None
        
    def set_output_callback(self, callback: Callable[[str, str], None]) -> None:
        """Set the callback for console output.
        
        Args:
            callback: Function to call with (message, level) for output
        """
        self.output_callback = callback
        
    def _output(self, message: str, level: str = "info") -> None:
        """Send output to the callback if available."""
        if self.output_callback:
            self.output_callback(message, level)
            
    def _load_modules(self) -> None:
        """Load all available modules."""
        try:
            module_list = self.module_loader.discover_modules()
            for module in module_list:
                self.modules[module.dotted_path] = module
            logger.info("Console modules loaded", count=len(self.modules))
        except Exception as e:
            logger.error("Failed to load console modules", error=str(e))
            
    def execute_command(self, command_line: str) -> str:
        """Execute a console command.
        
        Args:
            command_line: Full command line to execute
            
        Returns:
            Command output
        """
        self.command_history.append(command_line)
        command_line = command_line.strip()
        
        if not command_line:
            return ""
            
        # Handle session commands
        if self.active_session:
            return self._handle_session_command(command_line)
            
        # Parse command
        try:
            parts = shlex.split(command_line)
        except ValueError as e:
            return f"Error parsing command: {e}"
            
        if not parts:
            return ""
            
        command = parts[0].lower()
        args = parts[1:]
        
        # Route to appropriate handler
        command_handlers = {
            "help": self._handle_help,
            "show": self._handle_show,
            "use": self._handle_use,
            "set": self._handle_set,
            "unset": self._handle_unset,
            "run": self._handle_run,
            "exploit": self._handle_run,
            "back": self._handle_back,
            "info": self._handle_info,
            "search": self._handle_search,
            "sessions": self._handle_sessions,
            "session": self._handle_session,
            "exit": self._handle_exit,
            "quit": self._handle_exit,
            "clear": lambda args: "CLEAR_CONSOLE"
        }
        
        if command in command_handlers:
            return command_handlers[command](args)
        else:
            return f"Unknown command: {command}. Type 'help' for available commands."
            
    def _handle_help(self, args: List[str]) -> str:
        """Handle help command."""
        if not args:
            return """Core Commands
==============

    Command       Description
    -------       -----------
    back          Move back from the current context
    clear         Clear the console screen
    exit          Exit the console
    help          Help menu
    info          Display information about a module
    run           Execute the selected module
    search        Search for modules
    sessions      List active sessions
    session       Interact with a session
    set           Set a variable to a value
    show          Display modules of a given type
    unset         Unset one or more variables
    use           Select a module by name

Module Commands
===============

    Command       Description
    -------       -----------
    back          Return to the previous module
    info          Display information about the current module
    options       Display current module options
    run           Execute the current module
    set           Set a module option
    show payloads Show available payloads (for exploits)
    unset         Unset a module option

Session Commands (when in a session)
====================================

    Command       Description
    -------       -----------
    background    Background the current session
    exit          Exit the current session
    shell         Drop to system shell
    <command>     Execute command in the target system
"""
        else:
            # Help for specific command
            cmd = args[0].lower()
            help_text = {
                "use": "use <module_path>\n\nSelect a module to use. Example: use exploits/routers/dlink/dcs_930l_auth_rce",
                "set": "set <option> <value>\n\nSet a module option. Example: set target 192.168.1.1",
                "show": "show <type>\n\nShow modules of a type. Options: exploits, scanners, creds, payloads, encoders, all",
                "run": "run\n\nExecute the currently selected module.",
                "search": "search <term>\n\nSearch for modules containing the specified term.",
                "sessions": "sessions\n\nList all active sessions.",
                "session": "session <id>\n\nInteract with a specific session."
            }
            return help_text.get(cmd, f"No help available for '{cmd}'")
            
    def _handle_show(self, args: List[str]) -> str:
        """Handle show command."""
        if not args:
            return "Usage: show <type>\nTypes: exploits, scanners, creds, payloads, encoders, options, all"
            
        show_type = args[0].lower()
        
        if show_type == "options":
            if not self.current_module:
                return "No module selected. Use 'use <module>' first."
            return self._show_module_options()
        elif show_type == "payloads":
            if not self.current_module:
                return "No module selected. Use 'use <module>' first."
            return self._show_payloads()
        elif show_type in ["exploits", "scanners", "creds", "payloads", "encoders", "all"]:
            return self._show_modules(show_type)
        else:
            return f"Unknown show type: {show_type}"
            
    def _handle_use(self, args: List[str]) -> str:
        """Handle use command."""
        if not args:
            return "Usage: use <module_path>"
            
        module_path = args[0]
        
        # Find module
        if module_path in self.modules:
            self.current_module = self.modules[module_path]
            self.current_module_instance = self.current_module.cls()
            self.prompt = f"rsf ({self.current_module.name}) > "
            return f"Using module: {module_path}"
        else:
            # Try partial match
            matches = [path for path in self.modules.keys() if module_path in path]
            if len(matches) == 1:
                self.current_module = self.modules[matches[0]]
                self.current_module_instance = self.current_module.cls()
                self.prompt = f"rsf ({self.current_module.name}) > "
                return f"Using module: {matches[0]}"
            elif len(matches) > 1:
                return f"Multiple matches found:\n" + "\n".join(f"  {match}" for match in matches[:10])
            else:
                return f"Module not found: {module_path}"
                
    def _handle_set(self, args: List[str]) -> str:
        """Handle set command."""
        if len(args) < 2:
            return "Usage: set <option> <value>"
            
        if not self.current_module_instance:
            return "No module selected. Use 'use <module>' first."
            
        option_name = args[0]
        option_value = " ".join(args[1:])
        
        try:
            if hasattr(self.current_module_instance, option_name):
                # Convert value based on option type
                current_value = getattr(self.current_module_instance, option_name)
                converted_value = self._convert_option_value(option_value, current_value)
                setattr(self.current_module_instance, option_name, converted_value)
                return f"{option_name} => {converted_value}"
            else:
                return f"Unknown option: {option_name}"
        except Exception as e:
            return f"Error setting option: {e}"
            
    def _handle_unset(self, args: List[str]) -> str:
        """Handle unset command."""
        if not args:
            return "Usage: unset <option>"
            
        if not self.current_module_instance:
            return "No module selected. Use 'use <module>' first."
            
        option_name = args[0]
        
        try:
            if hasattr(self.current_module_instance, option_name):
                # Reset to default value
                default_value = getattr(self.current_module.cls(), option_name, "")
                setattr(self.current_module_instance, option_name, default_value)
                return f"Unset {option_name}"
            else:
                return f"Unknown option: {option_name}"
        except Exception as e:
            return f"Error unsetting option: {e}"
            
    def _handle_run(self, args: List[str]) -> str:
        """Handle run command."""
        if not self.current_module_instance:
            return "No module selected. Use 'use <module>' first."
            
        try:
            # Import runner system
            from .runner import RunnerManager
            
            # Initialize runner manager if not exists
            if not hasattr(self, '_runner_manager'):
                self._runner_manager = RunnerManager()
                
            # Check if already running
            if self._runner_manager.is_running():
                return "A module is already running. Please wait for it to complete."
                
            # Collect current module options with proper type conversion
            options = {}
            for opt_name in self.current_module.opts.keys():
                if hasattr(self.current_module_instance, opt_name):
                    raw_value = getattr(self.current_module_instance, opt_name)
                    # Process the option value through the same validation as web GUI
                    converted_value = self._process_option_value(raw_value, self.current_module.opts[opt_name])
                    options[opt_name] = converted_value
                    
            # Define completion callback
            def on_complete(success: bool, error_msg: Optional[str]) -> None:
                if success:
                    self._output("Module execution completed successfully", "success")
                    
                    # Check if a session was established
                    if hasattr(self.current_module_instance, 'session') and self.current_module_instance.session:
                        session_id = f"session_{len(self.sessions) + 1}"
                        session = RouterSploitSession(session_id, self.current_module_instance)
                        self.sessions[session_id] = session
                        self._output(f"Session {session_id} opened", "success")
                else:
                    self._output(f"Module execution failed: {error_msg}", "error")
                    
            # Start module execution
            started = self._runner_manager.start_module(
                self.current_module,
                options,
                self._output,  # Use existing output callback
                on_complete
            )
            
            if started:
                self._output("Starting module execution...", "info")
                self._output("Module is running in background. Output will appear below.", "info") 
                return "Module execution started. Please wait for results..."
            else:
                return "Failed to start module execution"
                
        except Exception as e:
            error_msg = f"Module execution failed: {str(e)}"
            self._output(error_msg, "error")
            return error_msg
            
    def _handle_back(self, args: List[str]) -> str:
        """Handle back command."""
        if self.active_session:
            self.active_session = None
            self.prompt = f"rsf ({self.current_module.name}) > " if self.current_module else "rsf > "
            return "Exited session"
        elif self.current_module:
            self.current_module = None
            self.current_module_instance = None
            self.prompt = "rsf > "
            return "Back to main menu"
        else:
            return "Already at main menu"
            
    def _handle_info(self, args: List[str]) -> str:
        """Handle info command."""
        if not self.current_module:
            return "No module selected. Use 'use <module>' first."
            
        info = f"""
       Name: {self.current_module.name}
       Path: {self.current_module.dotted_path}
   Category: {self.current_module.category}
Description: {self.current_module.description}

"""
        
        # Add options information
        if self.current_module.opts:
            info += "Options:\n"
            info += "=" * 60 + "\n"
            info += f"{'Name':<20} {'Current Setting':<20} {'Required':<10} {'Description'}\n"
            info += f"{'----':<20} {'---------------':<20} {'--------':<10} {'-----------'}\n"
            
            for opt_name, opt_info in self.current_module.opts.items():
                current_val = getattr(self.current_module_instance, opt_name, "") if self.current_module_instance else ""
                required = "yes" if opt_info.get('required', False) else "no"
                description = opt_info.get('description', '')
                info += f"{opt_name:<20} {str(current_val):<20} {required:<10} {description}\n"
                
        return info
        
    def _handle_search(self, args: List[str]) -> str:
        """Handle search command."""
        if not args:
            return "Usage: search <term>"
            
        search_term = args[0].lower()
        matches = []
        
        for path, module in self.modules.items():
            if (search_term in path.lower() or 
                search_term in module.name.lower() or 
                search_term in module.description.lower()):
                matches.append(module)
                
        if matches:
            result = f"Found {len(matches)} matching modules:\n\n"
            for module in sorted(matches, key=lambda m: m.dotted_path):
                result += f"  {module.dotted_path:<50} {module.description}\n"
            return result
        else:
            return f"No modules found matching '{search_term}'"
            
    def _handle_sessions(self, args: List[str]) -> str:
        """Handle sessions command."""
        if not self.sessions:
            return "No active sessions"
            
        result = "Active sessions:\n\n"
        result += f"{'ID':<10} {'Module':<30} {'Status'}\n"
        result += f"{'--':<10} {'------':<30} {'------'}\n"
        
        for session_id, session in self.sessions.items():
            status = "active" if session.is_active else "closed"
            module_name = session.module_instance.__class__.__name__ if session.module_instance else "unknown"
            result += f"{session_id:<10} {module_name:<30} {status}\n"
            
        return result
        
    def _handle_session(self, args: List[str]) -> str:
        """Handle session command."""
        if not args:
            return "Usage: session <session_id>"
            
        session_id = args[0]
        
        if session_id not in self.sessions:
            return f"Session not found: {session_id}"
            
        session = self.sessions[session_id]
        if not session.is_active:
            return f"Session {session_id} is not active"
            
        self.active_session = session_id
        self.prompt = f"session {session_id} > "
        return f"Entering session {session_id}. Type 'background' to return to console."
        
    def _handle_exit(self, args: List[str]) -> str:
        """Handle exit command."""
        return "EXIT_CONSOLE"
        
    def _handle_session_command(self, command_line: str) -> str:
        """Handle commands within an active session."""
        if not self.active_session or self.active_session not in self.sessions:
            self.active_session = None
            self.prompt = "rsf > "
            return "Session no longer available"
            
        session = self.sessions[self.active_session]
        command = command_line.strip()
        
        if command == "background":
            self.active_session = None
            self.prompt = f"rsf ({self.current_module.name}) > " if self.current_module else "rsf > "
            return "Backgrounded session"
        elif command == "exit":
            session.close()
            del self.sessions[self.active_session]
            self.active_session = None
            self.prompt = f"rsf ({self.current_module.name}) > " if self.current_module else "rsf > "
            return "Session closed"
        elif command == "shell":
            return "Dropping to system shell (interactive mode not supported in web interface)"
        else:
            # Execute command in session
            success, output = session.execute_command(command)
            return output
            
    def _show_modules(self, module_type: str) -> str:
        """Show modules of a specific type."""
        if module_type == "all":
            filtered_modules = list(self.modules.values())
        else:
            filtered_modules = [m for m in self.modules.values() if module_type in m.category.lower()]
            
        if not filtered_modules:
            return f"No {module_type} modules found"
            
        result = f"{module_type.capitalize()} Modules\n"
        result += "=" * 60 + "\n\n"
        
        # Group by category
        categories: Dict[str, List[ModuleMeta]] = {}
        for module in filtered_modules:
            cat = module.category
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(module)
            
        for category, modules in sorted(categories.items()):
            result += f"{category}\n"
            result += "-" * len(category) + "\n"
            for module in sorted(modules, key=lambda m: m.name):
                result += f"  {module.dotted_path:<50} {module.description}\n"
            result += "\n"
            
        return result
        
    def _show_module_options(self) -> str:
        """Show current module options."""
        if not self.current_module_instance:
            return "No module instance available"
            
        result = "Module Options:\n"
        result += "=" * 60 + "\n"
        result += f"{'Name':<20} {'Current Setting':<20} {'Required':<10} {'Description'}\n"
        result += f"{'----':<20} {'---------------':<20} {'--------':<10} {'-----------'}\n"
        
        for opt_name, opt_info in self.current_module.opts.items():
            current_val = getattr(self.current_module_instance, opt_name, "")
            required = "yes" if opt_info.get('required', False) else "no"
            description = opt_info.get('description', '')
            result += f"{opt_name:<20} {str(current_val):<20} {required:<10} {description}\n"
            
        return result
        
    def _show_payloads(self) -> str:
        """Show available payloads for current module."""
        if not self.current_module:
            return "No module selected"
            
        # Get payload modules
        payload_modules = [m for m in self.modules.values() if m.category == "Payload"]
        
        if not payload_modules:
            return "No payloads available"
            
        result = "Compatible Payloads:\n"
        result += "=" * 60 + "\n"
        
        for payload in sorted(payload_modules, key=lambda p: p.dotted_path):
            result += f"  {payload.dotted_path:<40} {payload.description}\n"
            
        return result
        
    def _convert_option_value(self, user_input: str, original_value: Any) -> Any:
        """Convert user input to the appropriate type based on the original value."""
        if isinstance(original_value, bool):
            return user_input.lower() in ('true', 'yes', '1', 'on', 'enable')
        elif isinstance(original_value, int):
            try:
                return int(user_input)
            except ValueError:
                return user_input
        elif isinstance(original_value, float):
            try:
                return float(user_input)
            except ValueError:
                return user_input
        else:
            return user_input
    
    def _process_option_value(self, raw_value: Any, option_spec: Dict[str, Any]) -> Any:
        """Process and validate option value for module execution.
        
        Args:
            raw_value: The raw value from the module instance
            option_spec: Option specification with metadata
            
        Returns:
            Processed value with correct type
        """
        # Get the default/original value from the spec
        original_value = option_spec.get('current_value')
        
        # If raw value is None, use the original/default value
        if raw_value is None:
            return original_value
        
        # If original value is None, return the raw value as string
        if original_value is None:
            return str(raw_value) if raw_value != "" else ""
        
        # Convert based on the type of the original value
        if isinstance(original_value, bool):
            if isinstance(raw_value, bool):
                return raw_value
            if isinstance(raw_value, str):
                return raw_value.lower() in ('true', '1', 'yes', 'on')
            return bool(raw_value)
        
        if isinstance(original_value, int):
            if isinstance(raw_value, int):
                return raw_value
            try:
                return int(raw_value)
            except (ValueError, TypeError):
                return original_value
        
        if isinstance(original_value, float):
            if isinstance(raw_value, float):
                return raw_value
            try:
                return float(raw_value)
            except (ValueError, TypeError):
                return original_value
        
        # Default to string
        return str(raw_value) if raw_value != "" else ""
            
    def cleanup(self) -> None:
        """Clean up console resources."""
        # Clean up runner manager
        if hasattr(self, '_runner_manager'):
            self._runner_manager.cleanup()
            
        # Close all sessions
        for session in self.sessions.values():
            session.close()
        self.sessions.clear()
            
    def get_prompt(self) -> str:
        """Get the current console prompt."""
        return self.prompt
        
    def get_command_history(self) -> List[str]:
        """Get command history."""
        return self.command_history.copy() 