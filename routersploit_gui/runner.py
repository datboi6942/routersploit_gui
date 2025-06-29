"""Thread-based module runner for RouterSploit exploits."""

import contextlib
import io
import queue
import sys
import threading
import traceback
from typing import Any, Callable, Dict, Optional, TextIO, Type

import structlog

from .module_loader import ModuleMeta

logger = structlog.get_logger(__name__)


class ModuleRunner(threading.Thread):
    """Executes RouterSploit modules in a background thread.
    
    Captures stdout/stderr and provides real-time output via callbacks.
    Complexity: O(1) for setup, O(n) where n is the module's execution time.
    """
    
    def __init__(
        self,
        module_meta: ModuleMeta,
        options: Dict[str, Any],
        on_output: Callable[[str, str], None],
        on_complete: Callable[[bool, Optional[str]], None],
    ) -> None:
        """Initialize the module runner.
        
        Args:
            module_meta: Metadata for the module to run
            options: Dictionary of module options
            on_output: Callback for output lines (line, level)
            on_complete: Callback for completion (success, error_msg)
        """
        super().__init__(daemon=True)
        self.module_meta = module_meta
        self.options = options
        self.on_output = on_output
        self.on_complete = on_complete
        self._stop_event = threading.Event()
        
        # Output queues for thread-safe communication
        self._output_queue: queue.Queue[tuple[str, str]] = queue.Queue()
        self._result_queue: queue.Queue[tuple[bool, Optional[str]]] = queue.Queue()
        
    def run(self) -> None:
        """Execute the module in the background thread."""
        success = False
        error_msg: Optional[str] = None
        
        try:
            logger.info(
                "Starting module execution",
                module=self.module_meta.dotted_path,
                options=self.options,
            )
            
            # Create and configure the module instance
            module_instance = self.module_meta.cls()
            self._configure_module(module_instance)
            
            # Execute with output capture
            with self._capture_output() as captured:
                module_instance.run()
                
            # Process captured output
            output_lines = captured.getvalue().splitlines()
            for line in output_lines:
                if line.strip():
                    self._queue_output(line, "info")
                    
            success = True
            logger.info("Module execution completed successfully")
            
        except KeyboardInterrupt:
            error_msg = "Execution cancelled by user"
            logger.info("Module execution cancelled")
            
        except Exception as e:
            error_msg = f"Module execution failed: {str(e)}"
            logger.error("Module execution failed", error=str(e))
            
            # Add traceback to output
            tb_lines = traceback.format_exc().splitlines()
            for line in tb_lines:
                self._queue_output(line, "error")
                
        finally:
            self.on_complete(success, error_msg)
            
    def _configure_module(self, module_instance: Any) -> None:
        """Configure the module instance with provided options.
        
        Args:
            module_instance: The instantiated module
        """
        print(f"[DEBUG] Starting _configure_module with {len(self.options)} options")
        print(f"[DEBUG] Options: {self.options}")
        
        for option_name, option_value in self.options.items():
            if hasattr(module_instance, option_name):
                # Get the original/default value from the module to determine expected type
                original_value = getattr(module_instance, option_name)
                
                print(f"[DEBUG] Processing option '{option_name}': value={option_value} (type: {type(option_value)}) original={original_value} (type: {type(original_value)})")
                
                # Convert the option value to the correct type
                converted_value = self._convert_option_type(option_value, original_value)
                
                print(f"[DEBUG] Converted '{option_name}' from {option_value} ({type(option_value)}) to {converted_value} ({type(converted_value)})")
                
                # Attempt to set the option with detailed error handling
                try:
                    print(f"[DEBUG] About to set {option_name} = {converted_value}")
                    setattr(module_instance, option_name, converted_value)
                    print(f"[DEBUG] Successfully set {option_name} = {converted_value}")
                except Exception as e:
                    error_msg = f"FAILED to set option '{option_name}': input_value={option_value} ({type(option_value)}), converted_value={converted_value} ({type(converted_value)}), original_value={original_value} ({type(original_value)}), error={str(e)}"
                    print(f"[ERROR] {error_msg}")
                    logger.error(error_msg)
                    # Print to stderr as well to ensure visibility
                    print(error_msg, file=sys.stderr)
                    raise RuntimeError(f"Failed to configure module option '{option_name}': {str(e)}") from e
            else:
                print(f"[DEBUG] Skipping option '{option_name}' - not found on module")
                logger.debug(f"Option '{option_name}' not found on module instance")
                
    def _convert_option_type(self, value: Any, original_value: Any) -> Any:
        """Convert option value to the correct type based on the original value.
        
        Args:
            value: The value to convert
            original_value: The original value from the module to determine type
            
        Returns:
            Converted value with correct type
        """
        print(f"[DEBUG] _convert_option_type: value={value} ({type(value)}) original_value={original_value} ({type(original_value)})")
        
        # If value is None, return original
        if value is None:
            print(f"[DEBUG] Value is None, returning original: {original_value}")
            return original_value
            
        # If original value is None, return as string
        if original_value is None:
            result = str(value) if value != "" else ""
            print(f"[DEBUG] Original is None, returning as string: {result}")
            return result
            
        # Handle boolean conversion (RouterSploit expects string representations)
        if isinstance(original_value, bool):
            print(f"[DEBUG] Original is boolean, converting value: {value}")
            if isinstance(value, bool):
                # Convert Python boolean to string that RouterSploit expects
                result = "true" if value else "false"
                print(f"[DEBUG] Converted Python boolean {value} to string '{result}'")
                return result
            elif isinstance(value, str):
                # Convert string to RouterSploit boolean format
                if value.lower() in ('true', '1', 'yes', 'on'):
                    result = "true"
                elif value.lower() in ('false', '0', 'no', 'off'):
                    result = "false"
                else:
                    print(f"[DEBUG] Unknown boolean string value: {value}")
                    result = "true" if original_value else "false"
                print(f"[DEBUG] Converted string '{value}' to RouterSploit boolean '{result}'")
                return result
            elif isinstance(value, (int, float)):
                result = "true" if value else "false"
                print(f"[DEBUG] Converted numeric {value} to RouterSploit boolean '{result}'")
                return result
            else:
                result = "true" if original_value else "false"
                print(f"[DEBUG] Unknown boolean type {type(value)}, using default '{result}'")
                return result
                
        # Handle integer values
        if isinstance(original_value, int):
            try:
                result = int(value)
                print(f"[DEBUG] Converted to integer: {result}")
                return result
            except (ValueError, TypeError):
                print(f"[DEBUG] Cannot convert to integer, returning as string: {value}")
                return str(value)
                
        # Handle float values
        if isinstance(original_value, float):
            try:
                result = float(value)
                print(f"[DEBUG] Converted to float: {result}")
                return result
            except (ValueError, TypeError):
                print(f"[DEBUG] Cannot convert to float, returning as string: {value}")
                return str(value)
                
        # Default: return as string
        result = str(value)
        print(f"[DEBUG] Default conversion to string: {result}")
        return result
        
    @contextlib.contextmanager
    def _capture_output(self) -> io.StringIO:
        """Context manager to capture stdout, stderr, and RouterSploit printer output.
        
        Returns:
            StringIO buffer containing captured output
        """
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        
        captured = io.StringIO()
        
        try:
            sys.stdout = captured
            sys.stderr = captured
            
            # Start monitoring RouterSploit's printer queue
            self._monitor_routersploit_output()
            
            yield captured
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            
    def _monitor_routersploit_output(self) -> None:
        """Monitor RouterSploit's printer queue for output in a separate thread."""
        def monitor_queue():
            """Monitor the RouterSploit printer queue and capture output."""
            try:
                from routersploit.core.exploit.printer import printer_queue
                import queue as queue_module
                
                # Continue monitoring while the runner is active
                while not self.is_stopped():
                    try:
                        # Get print items from RouterSploit's queue (with timeout)
                        print_item = printer_queue.get(timeout=0.1)
                        
                        # Extract the content and format it
                        content = print_item.content
                        sep = print_item.sep
                        end = print_item.end
                        
                        # Join the content parts and clean ANSI color codes for GUI display
                        output_text = sep.join(str(part) for part in content)
                        clean_text = self._clean_ansi_codes(output_text)
                        
                        # Determine the level based on color codes in the original content
                        level = self._determine_output_level(content)
                        
                        # Send to GUI
                        self._queue_output(clean_text, level)
                        
                        # Mark the queue item as done
                        printer_queue.task_done()
                        
                    except queue_module.Empty:
                        # No items in queue, continue monitoring
                        continue
                    except Exception as e:
                        logger.debug("Error monitoring RouterSploit queue", error=str(e))
                        break
                        
            except ImportError:
                logger.debug("RouterSploit printer not available")
            except Exception as e:
                logger.debug("Error setting up RouterSploit monitoring", error=str(e))
        
        # Start the monitoring thread
        monitor_thread = threading.Thread(target=monitor_queue, daemon=True)
        monitor_thread.start()
    
    def _clean_ansi_codes(self, text: str) -> str:
        """Remove ANSI color codes from text.
        
        Args:
            text: Text that may contain ANSI codes
            
        Returns:
            Clean text without ANSI codes
        """
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    def _determine_output_level(self, content: tuple) -> str:
        """Determine output level based on RouterSploit print prefixes.
        
        Args:
            content: Tuple of content parts from RouterSploit
            
        Returns:
            Output level string
        """
        if not content:
            return "info"
            
        first_part = str(content[0])
        if "[+]" in first_part:  # success
            return "success"
        elif "[-]" in first_part:  # error
            return "error"
        elif "[*]" in first_part:  # status
            return "info"
        elif "[!]" in first_part:  # warning
            return "warning"
        else:
            return "info"

    def _queue_output(self, line: str, level: str) -> None:
        """Queue an output line for the main thread.
        
        Args:
            line: The output line
            level: Output level (info, error, warning)
        """
        try:
            self.on_output(line, level)
        except Exception as e:
            logger.debug("Failed to queue output", error=str(e))
            
    def stop(self) -> None:
        """Request the runner to stop execution."""
        self._stop_event.set()
        logger.info("Stop requested for module runner")
        
    def is_stopped(self) -> bool:
        """Check if stop has been requested.
        
        Returns:
            True if stop has been requested
        """
        return self._stop_event.is_set()


class RunnerManager:
    """Manages multiple module runners and provides a simplified interface."""
    
    def __init__(self) -> None:
        """Initialize the runner manager."""
        self._current_runner: Optional[ModuleRunner] = None
        self._runners: list[ModuleRunner] = []
        
    def start_module(
        self,
        module_meta: ModuleMeta,
        options: Dict[str, Any],
        on_output: Callable[[str, str], None],
        on_complete: Callable[[bool, Optional[str]], None],
    ) -> bool:
        """Start executing a module.
        
        Args:
            module_meta: Metadata for the module to run
            options: Dictionary of module options
            on_output: Callback for output lines
            on_complete: Callback for completion
            
        Returns:
            True if started successfully, False if another module is running
        """
        if self._current_runner and self._current_runner.is_alive():
            logger.warning("Cannot start module, another is already running")
            return False
            
        self._current_runner = ModuleRunner(
            module_meta, options, on_output, on_complete
        )
        self._runners.append(self._current_runner)
        self._current_runner.start()
        
        logger.info("Started module runner", module=module_meta.dotted_path)
        return True
        
    def stop_current(self) -> None:
        """Stop the currently running module."""
        if self._current_runner and self._current_runner.is_alive():
            self._current_runner.stop()
            logger.info("Stopping current module runner")
            
    def is_running(self) -> bool:
        """Check if a module is currently running.
        
        Returns:
            True if a module is running
        """
        return (
            self._current_runner is not None
            and self._current_runner.is_alive()
        )
        
    def update(self) -> None:
        """Update the runner manager state.
        
        This method can be called periodically to perform maintenance tasks
        like cleaning up finished threads.
        """
        # Clean up finished runners
        self._runners = [r for r in self._runners if r.is_alive()]
        
        # Check if current runner has finished and clear it (no excessive logging)
        if self._current_runner and not self._current_runner.is_alive():
            self._current_runner = None
        
    def cleanup(self) -> None:
        """Clean up all runners."""
        self.stop_current()
        
        # Wait for all runners to complete
        for runner in self._runners:
            if runner.is_alive():
                runner.join(timeout=5.0)
                
        self._runners.clear()
        self._current_runner = None
        logger.info("Cleaned up all runners") 