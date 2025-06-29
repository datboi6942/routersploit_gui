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

logger = structlog.get_logger(__name__)


class RouterSploitWebGUI:
    """Flask-based web GUI for RouterSploit.
    
    Provides a modern web interface for discovering, configuring,
    and executing RouterSploit modules with real-time output.
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
        
        # Application state
        self.modules: List[ModuleMeta] = []
        self.module_tree: Dict[str, Any] = {}
        self.current_module: Optional[ModuleMeta] = None
        self.target_history: List[str] = []
        
        # Setup routes and socket handlers
        self._setup_routes()
        self._setup_socket_handlers()
        
        # Load modules
        self._load_modules()
        
    def _setup_routes(self) -> None:
        """Setup Flask routes."""
        
        @self.app.route('/')
        def index() -> str:
            """Main page."""
            return render_template('index.html')
        
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
                payloads = self._get_available_payloads()
            
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
                'is_exploit': self._is_exploit_module(module)
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
            
            # Validate and convert options
            processed_options = self._process_options(options, module.opts)
            
            # Add payload options if specified
            if payload_path:
                payload = self._find_module_by_path(payload_path)
                if payload:
                    processed_payload_options = self._process_options(payload_options, payload.opts)
                    # Set the payload on the module
                    processed_options['payload'] = payload.cls()
                    # Configure payload options
                    for opt_name, opt_value in processed_payload_options.items():
                        if hasattr(processed_options['payload'], opt_name):
                            setattr(processed_options['payload'], opt_name, opt_value)
            
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
                    'category': value.category
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
                            'category': child_value.category
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
        
        for opt_name, opt_value in options.items():
            if opt_name in option_specs:
                spec = option_specs[opt_name]
                original_value = spec.get('current_value')
                
                # Convert the value to the appropriate type
                try:
                    converted_value = self._convert_option_value(opt_value, original_value)
                    processed[opt_name] = converted_value
                except (ValueError, TypeError) as e:
                    logger.warning("Invalid option value", option=opt_name, value=opt_value, error=str(e))
                    # Use default value if conversion fails
                    processed[opt_name] = original_value
            else:
                # Unknown option, pass through as-is
                processed[opt_name] = opt_value
        
        return processed
    
    def _convert_option_value(self, user_input: Any, original_value: Any) -> Any:
        """Convert user input to the appropriate type based on original value.
        
        Args:
            user_input: Value from user input
            original_value: Original value from the module
            
        Returns:
            Converted value with appropriate type
        """
        if user_input == "" or user_input is None:
            return original_value
        
        # If original value is None, return the input as string
        if original_value is None:
            return str(user_input)
        
        # Convert based on the type of the original value
        if isinstance(original_value, bool):
            if isinstance(user_input, bool):
                return user_input
            if isinstance(user_input, str):
                return user_input.lower() in ('true', '1', 'yes', 'on')
            return bool(user_input)
        
        if isinstance(original_value, int):
            return int(user_input)
        
        if isinstance(original_value, float):
            return float(user_input)
        
        # Default to string
        return str(user_input)
    
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