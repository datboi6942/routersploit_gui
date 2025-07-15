"""Flask-based web GUI for RouterSploit."""

import json
import threading
from typing import Any, Dict, List, Optional

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import structlog

from . import config
from .module_loader import ModuleLoader, ModuleMeta
from .runner import RunnerManager
from .console import ConsoleHandler
from .auto_own_runner import AutoOwnManager

logger = structlog.get_logger(__name__)


class RouterSploitWebGUI:
    """Flask-based web GUI for RouterSploit.
    
    Provides a modern web interface for discovering, configuring,
    and executing RouterSploit modules with real-time output.
    Also includes a console interface for complete RouterSploit functionality.
    """
    
    def __init__(self, host: str = "127.0.0.1", port: int = 5000) -> None:
        """Initialize the web GUI.
        
        Args:
            host: Host to bind the web server to
            port: Port to bind the web server to
        """
        self.host = host
        self.port = port
        
        # Initialize Flask app
        self.app = Flask(__name__, 
                        template_folder='templates',
                        static_folder='static')
        self.app.config['SECRET_KEY'] = 'routersploit-gui-secret-key'
        
        # Initialize SocketIO for real-time communication
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Initialize backend components
        self.module_loader = ModuleLoader()
        self.runner_manager = RunnerManager()
        self.console_handler = ConsoleHandler(self.module_loader)
        self.auto_own_manager = AutoOwnManager()
        
        # Application state
        self.modules: List[ModuleMeta] = []
        self.module_tree: Dict[str, Any] = {}
        self.current_module: Optional[ModuleMeta] = None
        self.target_history: List[str] = []
        
        # Console clients tracking
        self.console_clients: Dict[str, bool] = {}  # session_id -> is_active
        
        # Setup routes and socket handlers
        self._setup_routes()
        self._setup_socket_handlers()
        
        # Setup console output callback
        self.console_handler.set_output_callback(self._on_console_output)
        
        # Load modules
        self._load_modules()
        
    def _setup_routes(self) -> None:
        """Setup Flask routes."""
        
        @self.app.route('/')
        def index() -> str:
            """Main page."""
            return render_template('index.html')
        
        @self.app.route('/sw.js')
        def service_worker() -> Any:
            """Service worker for PWA functionality."""
            from flask import send_from_directory
            import os
            static_dir = os.path.join(os.path.dirname(__file__), 'static')
            return send_from_directory(static_dir, 'sw.js', mimetype='application/javascript')
        
        @self.app.route('/api/modules')
        def get_modules() -> Any:
            """Get all modules as a tree structure."""
            # Convert the tree to a JSON-serializable format
            json_tree = self._serialize_tree(self.module_tree)
            return jsonify({
                'tree': json_tree,
                'count': len(self.modules)
            })
        
        @self.app.route('/api/module/<path:module_path>')
        def get_module(module_path: str) -> Any:
            """Get details for a specific module."""
            module = self._find_module_by_path(module_path)
            if not module:
                return jsonify({'error': 'Module not found'}), 404
            
            # Get available payloads if this is an exploit module
            payloads = []
            if self._is_exploit_module(module):
                payloads = self._get_compatible_payloads(module)
            
            # Serialize the module options
            json_options = self._serialize_options(module.opts)
            
            return jsonify({
                'name': module.name,
                'description': module.description,
                'path': module.dotted_path,
                'category': module.category,
                'options': json_options,
                'payloads': [{'name': p.name, 'path': p.dotted_path, 'options': self._serialize_options(p.opts)} 
                           for p in payloads],
                'is_exploit': self._is_exploit_module(module),
                'cve_list': module.cve_list
            })
        
        @self.app.route('/api/run', methods=['POST'])
        def run_module() -> Any:
            """Execute a module with provided options."""
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            module_path = data.get('module_path')
            options = data.get('options', {})
            payload_path = data.get('payload_path')
            payload_options = data.get('payload_options', {})
            
            module = self._find_module_by_path(module_path)
            if not module:
                return jsonify({'error': 'Module not found'}), 404

            logger.info("Processing module options", module=module_path, options=options)
            
            # Validate and convert options
            processed_options = self._process_options(options, module.opts)
            
            logger.info("Processed module options", processed_options=processed_options)
            
            # Add payload options if specified
            if payload_path:
                payload = self._find_module_by_path(payload_path)
                if payload:
                    logger.info("Processing payload options", payload=payload_path, payload_options=payload_options)
                    processed_payload_options = self._process_options(payload_options, payload.opts)
                    logger.info("Processed payload options", processed_payload_options=processed_payload_options)
                    
                    # Set the payload on the module
                    processed_options['payload'] = payload.cls()
                    
                    # Configure payload options with detailed error handling
                    for opt_name, opt_value in processed_payload_options.items():
                        if hasattr(processed_options['payload'], opt_name):
                            try:
                                logger.info("Setting payload option", option=opt_name, value=opt_value, value_type=type(opt_value).__name__)
                                setattr(processed_options['payload'], opt_name, opt_value)
                                logger.info("Successfully set payload option", option=opt_name)
                            except Exception as e:
                                logger.error("Failed to set payload option", option=opt_name, value=opt_value, value_type=type(opt_value).__name__, error=str(e))
                                return jsonify({'error': f'Failed to set payload option {opt_name}: {str(e)}'}), 400
            
            # Start execution
            success = self.runner_manager.start_module(
                module,
                processed_options,
                self._on_module_output,
                self._on_module_complete
            )
            
            if success:
                self.current_module = module
                return jsonify({'status': 'started'})
            else:
                return jsonify({'error': 'Failed to start module'}), 500
        
        @self.app.route('/api/stop', methods=['POST'])
        def stop_module() -> Any:
            """Stop the currently running module."""
            self.runner_manager.stop_current()
            return jsonify({'status': 'stopped'})
        
        @self.app.route('/api/status')
        def get_status() -> Any:
            """Get current execution status."""
            return jsonify({
                'running': self.runner_manager.is_running(),
                'current_module': self.current_module.dotted_path if self.current_module else None
            })
        
        @self.app.route('/api/auto-own/start', methods=['POST'])
        def start_auto_own() -> Any:
            """Start an auto-own process."""
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            target = data.get('target')
            verbose = bool(data.get('verbose', False))
            debug = bool(data.get('debug', False))
            if not target:
                return jsonify({'error': 'Target not specified'}), 400
            
            # Check if auto-own is enabled
            if not config.AUTO_OWN_ENABLED:
                return jsonify({'error': 'Auto-Own feature is disabled'}), 403
            
            # Check if OpenAI is configured
            if not config.get_openai_api_key():
                return jsonify({'error': 'OpenAI API key not configured'}), 403
            
            # Start auto-own process
            success = self.auto_own_manager.start_auto_own(
                target=target,
                on_output=self._on_auto_own_output,
                on_complete=self._on_auto_own_complete,
                on_progress=self._on_auto_own_progress,
                verbose=verbose,
                debug=debug
            )
            
            if success:
                return jsonify({'status': 'started', 'target': target})
            else:
                return jsonify({'error': 'Failed to start auto-own process'}), 500
        
        @self.app.route('/api/auto-own/stop', methods=['POST'])
        def stop_auto_own() -> Any:
            """Stop the current auto-own process."""
            self.auto_own_manager.stop_current()
            return jsonify({'status': 'stopped'})
        
        @self.app.route('/api/auto-own/status')
        def get_auto_own_status() -> Any:
            """Get auto-own status and configuration."""
            return jsonify(self.auto_own_manager.get_status())
        
        @self.app.route('/api/auto-own/targets')
        def get_auto_own_targets() -> Any:
            """Get list of targets with auto-own history."""
            targets = self.auto_own_manager.agent.get_available_targets()
            return jsonify({'targets': targets})
        
        @self.app.route('/api/auto-own/history/<target>')
        def get_auto_own_history(target: str) -> Any:
            """Get auto-own history for a specific target."""
            history = self.auto_own_manager.get_target_history(target)
            return jsonify({'history': history})
        
        @self.app.route('/api/auto-own/set-api-key', methods=['POST'])
        def set_auto_own_api_key() -> Any:
            """Set the OpenAI API key for Auto-Own."""
            data = request.get_json()
            if not data or 'api_key' not in data:
                return jsonify({'error': 'No API key provided'}), 400
            try:
                config.set_openai_api_key(data['api_key'])
                return jsonify({'status': 'success'})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
    
    def _setup_socket_handlers(self) -> None:
        """Setup SocketIO event handlers."""
        
        @self.socketio.on('connect')
        def handle_connect() -> None:
            """Handle client connection."""
            logger.info("Client connected")
            emit('status', {
                'running': self.runner_manager.is_running(),
                'current_module': self.current_module.dotted_path if self.current_module else None
            })
        
        @self.socketio.on('disconnect')
        def handle_disconnect() -> None:
            """Handle client disconnection."""
            logger.info("Client disconnected")
            
        @self.socketio.on('console_connect')
        def handle_console_connect() -> None:
            """Handle console connection."""
            session_id = request.sid
            self.console_clients[session_id] = True
            logger.info("Console client connected", session_id=session_id)
            emit('console_connected', {
                'prompt': self.console_handler.get_prompt(),
                'welcome': 'RouterSploit Console - Type "help" for commands'
            })
            
        @self.socketio.on('console_disconnect')
        def handle_console_disconnect() -> None:
            """Handle console disconnection."""
            session_id = request.sid
            if session_id in self.console_clients:
                del self.console_clients[session_id]
            logger.info("Console client disconnected", session_id=session_id)
            
        @self.socketio.on('console_command')
        def handle_console_command(data: Dict[str, Any]) -> None:
            """Handle console command execution."""
            try:
                command = data.get('command', '').strip()
                if not command:
                    return
                    
                logger.info("Executing console command", command=command)
                
                # Execute the command
                result = self.console_handler.execute_command(command)
                
                # Handle special commands
                if result == "CLEAR_CONSOLE":
                    emit('console_clear')
                    return
                elif result == "EXIT_CONSOLE":
                    emit('console_exit')
                    return
                
                # Send result back to client
                if result:
                    emit('console_output', {
                        'data': result,
                        'level': 'info'
                    })
                
                # Send updated prompt
                emit('console_prompt', {
                    'prompt': self.console_handler.get_prompt()
                })
                
            except Exception as e:
                logger.error("Console command failed", error=str(e))
                emit('console_output', {
                    'data': f"Error: {str(e)}",
                    'level': 'error'
                })
    
    def _on_console_output(self, message: str, level: str) -> None:
        """Handle console output from the console handler."""
        # Broadcast to all connected console clients
        self.socketio.emit('console_output', {
            'data': message,
            'level': level
        }, room=None)  # Broadcast to all clients
    
    def _load_modules(self) -> None:
        """Load all RouterSploit modules."""
        try:
            logger.info("Loading RouterSploit modules...")
            self.modules = self.module_loader.discover_modules()
            self.module_tree = self.module_loader.build_tree()
            logger.info("Modules loaded successfully", count=len(self.modules))
        except Exception as e:
            logger.error("Failed to load modules", error=str(e))
            raise
    
    def _find_module_by_path(self, path: str) -> Optional[ModuleMeta]:
        """Find a module by its dotted path."""
        for module in self.modules:
            if module.dotted_path == path:
                return module
        return None
    
    def _is_exploit_module(self, module: ModuleMeta) -> bool:
        """Check if a module is an exploit module."""
        return module.category == "exploits"
    
    def _get_available_payloads(self) -> List[ModuleMeta]:
        """Get all available payload modules."""
        return [module for module in self.modules if module.category == "payloads"]
    
    def _get_compatible_payloads(self, exploit_module: ModuleMeta) -> List[ModuleMeta]:
        """Get payloads compatible with the given exploit module.
        
        Args:
            exploit_module: The exploit module to find compatible payloads for
            
        Returns:
            List of compatible payload modules
        """
        all_payloads = self._get_available_payloads()
        
        # For now, filter based on common patterns and payload types
        # This can be enhanced with more sophisticated compatibility logic
        
        compatible_payloads = []
        exploit_path = exploit_module.dotted_path.lower()
        
        for payload in all_payloads:
            payload_path = payload.dotted_path.lower()
            
            # Include all generic payloads (cmd, generic)
            if any(term in payload_path for term in ["cmd.", "generic"]):
                compatible_payloads.append(payload)
                continue
            
            # Architecture-specific filtering
            # If exploit targets specific architecture, prefer matching payloads
            arch_hints = {
                "arm": ["arm", "armle", "armbe"],
                "mips": ["mips", "mipsle", "mipsbe"], 
                "x86": ["x86", "x64"],
                "sparc": ["sparc"],
                "ppc": ["ppc", "powerpc"]
            }
            
            # Check if exploit hints at specific architecture
            exploit_arch = None
            for arch, variants in arch_hints.items():
                if any(variant in exploit_path for variant in variants):
                    exploit_arch = arch
                    break
            
            # If we found architecture hints, prefer matching payloads
            if exploit_arch:
                arch_variants = arch_hints[exploit_arch]
                if any(variant in payload_path for variant in arch_variants):
                    compatible_payloads.append(payload)
                # Also include generic payloads for arch-specific exploits
                elif any(term in payload_path for term in ["generic", "cmd"]):
                    compatible_payloads.append(payload)
            else:
                # No specific architecture detected, include most payloads except very specific ones
                # Exclude architecture-specific payloads when no arch hints
                if not any(arch_var in payload_path for arch_vars in arch_hints.values() for arch_var in arch_vars):
                    compatible_payloads.append(payload)
                # But always include cmd payloads as they're usually universal
                elif "cmd." in payload_path:
                    compatible_payloads.append(payload)
        
        # Remove duplicates and sort by name
        seen = set()
        unique_payloads = []
        for payload in compatible_payloads:
            if payload.dotted_path not in seen:
                seen.add(payload.dotted_path)
                unique_payloads.append(payload)
        
        return sorted(unique_payloads, key=lambda p: p.name)
    
    def _serialize_tree(self, tree: Dict[str, Any]) -> Dict[str, Any]:
        """Convert the module tree to a JSON-serializable format.
        
        Args:
            tree: The module tree to serialize
            
        Returns:
            JSON-serializable dictionary with proper structure
        """
        serialized = {}
        
        for key, value in tree.items():
            if hasattr(value, 'dotted_path'):  # This is a ModuleMeta object
                # Convert ModuleMeta to dict
                serialized[key] = {
                    'name': value.name,
                    'description': value.description,
                    'dotted_path': value.dotted_path,
                    'category': value.category,
                    'cve_list': getattr(value, 'cve_list', [])
                }
            elif isinstance(value, dict):
                # This is a nested category - separate modules and subcategories
                modules = []
                categories = {}
                
                for child_key, child_value in value.items():
                    if hasattr(child_value, 'dotted_path'):  # ModuleMeta object
                        modules.append({
                            'name': child_value.name,
                            'description': child_value.description,
                            'dotted_path': child_value.dotted_path,
                            'category': child_value.category,
                            'cve_list': getattr(child_value, 'cve_list', [])
                        })
                    elif isinstance(child_value, dict):
                        # Recursive call for nested categories
                        categories[child_key] = self._serialize_tree({child_key: child_value})[child_key]
                
                # Only include modules and categories if they exist
                category_data = {}
                if modules:
                    category_data['modules'] = modules
                if categories:
                    category_data['categories'] = categories
                
                serialized[key] = category_data
            else:
                # Fallback for any other type
                serialized[key] = str(value)
        
        return serialized
    
    def _serialize_options(self, options: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Convert module options to a JSON-serializable format.
        
        Args:
            options: The options dictionary to serialize
            
        Returns:
            JSON-serializable dictionary
        """
        serialized = {}
        
        for opt_name, opt_info in options.items():
            serialized_option = {}
            
            for key, value in opt_info.items():
                # Convert non-serializable objects to strings or appropriate types
                if hasattr(value, '__call__'):  # Function/method
                    serialized_option[key] = str(value)
                elif hasattr(value, '__dict__'):  # Complex object
                    serialized_option[key] = str(value)
                else:
                    # Basic types that are JSON serializable
                    serialized_option[key] = value
            
            serialized[opt_name] = serialized_option
        
        return serialized
    
    def _process_options(self, options: Dict[str, Any], option_specs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Process and validate options from the web interface.
        
        Args:
            options: Raw options from the web interface
            option_specs: Option specifications from the module
            
        Returns:
            Processed and validated options
        """
        processed = {}
        
        logger.info("Processing options", raw_options=options, spec_count=len(option_specs))
        
        for opt_name, opt_value in options.items():
            if opt_name in option_specs:
                spec = option_specs[opt_name]
                original_value = spec.get('current_value')
                
                logger.info("Processing option", option=opt_name, input_value=opt_value, input_type=type(opt_value).__name__, original_value=original_value, original_type=type(original_value).__name__)
                
                # Convert the value to the appropriate type
                try:
                    converted_value = self._convert_option_value(opt_value, original_value)
                    processed[opt_name] = converted_value
                    logger.info("Successfully converted option", option=opt_name, converted_value=converted_value, converted_type=type(converted_value).__name__)
                except (ValueError, TypeError) as e:
                    logger.warning("Invalid option value", option=opt_name, value=opt_value, error=str(e))
                    # Use default value if conversion fails
                    processed[opt_name] = original_value
                    logger.info("Using default value for option", option=opt_name, default_value=original_value)
            else:
                # Unknown option, pass through as-is
                logger.warning("Unknown option, passing through", option=opt_name, value=opt_value)
                processed[opt_name] = opt_value
        
        logger.info("Finished processing options", processed_options=processed)
        return processed
    
    def _convert_option_value(self, user_input: Any, original_value: Any) -> Any:
        """Convert user input to the appropriate type based on original value.
        
        Args:
            user_input: Value from user input
            original_value: Original value from the module
            
        Returns:
            Converted value with appropriate type
        """
        logger.debug("Converting option value", user_input=user_input, user_input_type=type(user_input).__name__, original_value=original_value, original_type=type(original_value).__name__)
        
        if user_input == "" or user_input is None:
            logger.debug("Input is empty or None, returning original", result=original_value)
            return original_value
        
        # If original value is None, return the input as string
        if original_value is None:
            result = str(user_input)
            logger.debug("Original is None, converting to string", result=result)
            return result
        
        # Convert based on the type of the original value
        if isinstance(original_value, bool):
            logger.debug("Converting to boolean", user_input=user_input, user_input_type=type(user_input).__name__)
            
            if isinstance(user_input, bool):
                logger.debug("Input is already boolean", result=user_input)
                return user_input
                
            if isinstance(user_input, str):
                result = user_input.lower() in ('true', '1', 'yes', 'on')
                logger.debug("Converting string to boolean", string_input=user_input, lower_input=user_input.lower(), result=result)
                return result
                
            result = bool(user_input)
            logger.debug("Converting other type to boolean", input_value=user_input, result=result)
            return result
        
        if isinstance(original_value, int):
            result = int(user_input)
            logger.debug("Converting to int", user_input=user_input, result=result)
            return result
        
        if isinstance(original_value, float):
            result = float(user_input)
            logger.debug("Converting to float", user_input=user_input, result=result)
            return result
        
        # Default to string
        result = str(user_input)
        logger.debug("Converting to string (default)", user_input=user_input, result=result)
        return result
    
    def _on_module_output(self, line: str, level: str) -> None:
        """Handle output from running module."""
        self.socketio.emit('output', {
            'line': line,
            'level': level,
            'timestamp': threading.current_thread().ident
        })
    
    def _on_module_complete(self, success: bool, error_msg: Optional[str]) -> None:
        """Handle module completion."""
        self.current_module = None
        self.socketio.emit('complete', {
            'success': success,
            'error': error_msg
        })
    
    def _on_auto_own_output(self, line: str, level: str) -> None:
        """Handle auto-own output."""
        self.socketio.emit('auto_own_output', {
            'line': line,
            'level': level
        })
        logger.info("Auto-own output", line=line, level=level)
    
    def _on_auto_own_complete(self, success: bool, error_msg: Optional[str]) -> None:
        """Handle auto-own completion."""
        self.socketio.emit('auto_own_complete', {
            'success': success,
            'error': error_msg
        })
        logger.info("Auto-own process completed", success=success, error=error_msg)
    
    def _on_auto_own_progress(self, status: str, percentage: float) -> None:
        """Handle auto-own progress updates."""
        self.socketio.emit('auto_own_progress', {
            'status': status,
            'percentage': percentage
        })
        logger.info("Auto-own progress", status=status, percentage=percentage)
    
    def run(self, debug: bool = False) -> None:
        """Start the web server.
        
        Args:
            debug: Whether to run in debug mode
        """
        logger.info("Starting RouterSploit Web GUI", host=self.host, port=self.port)
        print(f"\nRouterSploit GUI is starting...")
        print(f"Open your browser and go to: http://{self.host}:{self.port}")
        print("Press Ctrl+C to stop the server\n")
        
        self.socketio.run(
            self.app,
            host=self.host,
            port=self.port,
            debug=debug,
            allow_unsafe_werkzeug=True
        )
    
    def cleanup(self) -> None:
        """Cleanup resources."""
        self.runner_manager.cleanup()
        self.console_handler.cleanup()
        self.auto_own_manager.cleanup()


def create_app() -> Flask:
    """Factory function to create Flask app."""
    gui = RouterSploitWebGUI()
    return gui.app


def main() -> None:
    """Main entry point for the web GUI."""
    import argparse
    
    parser = argparse.ArgumentParser(description="RouterSploit Web GUI")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind to")
    parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    
    args = parser.parse_args()
    
    gui = RouterSploitWebGUI(host=args.host, port=args.port)
    try:
        gui.run(debug=args.debug)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        gui.cleanup()


if __name__ == "__main__":
    main() 