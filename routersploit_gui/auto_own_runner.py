"""Auto-Own runner for LLM agent execution."""

import json
import threading
import time
from typing import Any, Callable, Dict, Optional, List

import structlog

from . import config
from .llm_agent import AutoOwnAgent

logger = structlog.get_logger(__name__)


class AutoOwnRunner(threading.Thread):
    """Executes Auto-Own LLM agent in a background thread.
    
    Captures output and provides real-time updates via callbacks.
    Complexity: O(1) for setup, O(n) where n is the agent's execution time.
    """
    
    def __init__(
        self,
        target: str,
        on_output: Callable[[str, str], None],
        on_complete: Callable[[bool, Optional[str]], None],
        on_progress: Callable[[str, float], None],
        verbose: bool = False,
        debug: bool = False,
    ) -> None:
        """Initialize the auto-own runner.
        
        Args:
            target: Target IP address or hostname
            on_output: Callback for output lines (line, level)
            on_complete: Callback for completion (success, error_msg)
            on_progress: Callback for progress updates (status, percentage)
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
        """
        super().__init__(daemon=True)
        self.target = target
        self.on_output = on_output
        self.on_complete = on_complete
        self.on_progress = on_progress
        self._stop_event = threading.Event()
        
        # Initialize the LLM agent
        self.agent = AutoOwnAgent()
        
        # Progress tracking
        self.current_step = 0
        self.total_steps = 6  # scan, analyze, search, generate, test, summarize
        self.verbose = verbose
        self.debug = debug
        
    def run(self) -> None:
        """Execute the auto-own process in the background thread."""
        success = False
        error_msg: Optional[str] = None
        start_time = time.time()
        
        try:
            logger.info("Starting auto-own process", target=self.target)
            self._output("Starting Auto-Own process...", "info")
            self._progress("Initializing", 0.0)
            if self.verbose:
                self._output("[Verbose] Preparing to initialize LLM agent.", "info")
            if self.debug:
                self._output(f"🐛 [DEBUG] Auto-Own process started at {time.strftime('%H:%M:%S')}", "warning")
                self._output(f"🐛 [DEBUG] Target: {self.target}, Verbose: {self.verbose}, Debug: {self.debug}", "warning")
                
            # Check if auto-own is enabled
            if not config.AUTO_OWN_ENABLED:
                error_msg = "Auto-Own feature is disabled"
                self._output(f"ERROR: {error_msg}", "error")
                return
                
            # Check OpenAI API key
            if not config.get_openai_api_key():
                error_msg = "OpenAI API key not configured"
                self._output(f"ERROR: {error_msg}", "error")
                return
                
            # Step 1: Initialize agent
            step_start = time.time()
            self._progress("Initializing LLM agent", 10.0)
            self._output("Initializing LLM agent...", "info")
            if self.verbose:
                self._output("[Verbose] LLM agent object created. Sleeping 1s to simulate init.", "info")
            if self.debug:
                self._output(f"🐛 [DEBUG] Agent initialization started", "warning")
            time.sleep(1)  # Simulate initialization time
            step_elapsed = time.time() - step_start
            if self.debug:
                self._output(f"🐛 [DEBUG] Agent initialization completed in {step_elapsed:.1f}s", "warning")
            
            # Step 2: Start auto-own process
            step_start = time.time()
            self._progress("Starting vulnerability assessment", 20.0)
            self._output(f"Starting vulnerability assessment on {self.target}...", "info")
            if self.verbose:
                self._output(f"[Verbose] Running comprehensive nmap scan on {self.target} (common ports)", "info")
            if self.debug:
                self._output(f"🐛 [DEBUG] Calling agent.auto_own_target with target={self.target}, verbose={self.verbose}, debug={self.debug}", "warning")
                
            # Execute the auto-own process
            results = self.agent.auto_own_target(
                self.target, 
                verbose=self.verbose, 
                debug=self.debug,
                on_output=self._debug_agent_output if self.debug else (self._output if self.verbose else None)
            )
            
            step_elapsed = time.time() - step_start
            if self.verbose:
                self._output("[Verbose] nmap scan and analysis complete. Passing results to LLM.", "info")
            if self.debug:
                self._output(f"🐛 [DEBUG] Agent execution completed in {step_elapsed:.1f}s", "warning")
                self._output(f"🐛 [DEBUG] Agent returned results: {str(results)[:200]}{'...' if len(str(results)) > 200 else ''}", "warning")

            if "error" in results:
                error_msg = results["error"]
                self._output(f"ERROR: {error_msg}", "error")
                return
                
            # Step 3: Process results
            step_start = time.time()
            self._progress("Processing results", 80.0)
            if self.debug:
                self._output(f"🐛 [DEBUG] Processing and formatting results", "warning")
            
            # Extract key information for user
            scan_results = results.get("conversation_history", [])
            target_info = results.get("target", self.target)
            
            # Show summary
            self._progress("Generating summary", 90.0)
            self._output(f"✅ Auto-Own process completed for {target_info}", "success")
            
            # Show final summary if available
            final_summary = results.get("final_summary", "")
            if final_summary:
                self._output("📋 Final Summary:", "info")
                # Break summary into readable chunks
                for line in final_summary.split('\n'):
                    if line.strip():
                        self._output(f"   {line.strip()}", "info")
            
            step_elapsed = time.time() - step_start
            total_elapsed = time.time() - start_time
            
            if self.debug:
                self._output(f"🐛 [DEBUG] Results processing completed in {step_elapsed:.1f}s", "warning")
                self._output(f"🐛 [DEBUG] Total process time: {total_elapsed:.1f}s", "warning")
            
            self._progress("Complete", 100.0)
            self._output(f"🕒 Total execution time: {total_elapsed:.1f} seconds", "info")
            success = True
            
        except Exception as e:
            total_elapsed = time.time() - start_time
            error_msg = f"Auto-own process failed: {str(e)}"
            logger.error(error_msg, target=self.target, error=str(e))
            self._output(f"❌ ERROR: {error_msg}", "error")
            if self.debug:
                self._output(f"🐛 [DEBUG] Exception after {total_elapsed:.1f}s: {error_msg}", "error")
                self._output(f"🐛 [DEBUG] Exception type: {type(e).__name__}", "error")
                
        finally:
            if self.on_complete:
                self.on_complete(success, error_msg)
            
    def _output(self, line: str, level: str = "info") -> None:
        """Send output line to callback."""
        if self.on_output:
            self.on_output(line, level)
    
    def _debug_agent_output(self, line: str, level: str = "info") -> None:
        """Send debug output line with special formatting."""
        if self.on_output:
            if level == "info":
                level = "warning"  # Make debug messages more visible
            self.on_output(f"🐛 [DEBUG-AGENT] {line}", level)
    
    def _progress(self, status: str, percentage: float) -> None:
        """Send progress update to callback."""
        if self.on_progress:
            self.on_progress(status, percentage)
            
    def stop(self) -> None:
        """Stop the auto-own process."""
        self._stop_event.set()
        logger.info("Auto-own process stop requested")
        
    def is_stopped(self) -> bool:
        """Check if the process has been stopped.
        
        Returns:
            True if stopped, False otherwise
        """
        return self._stop_event.is_set()


class AutoOwnManager:
    """Manages auto-own execution and provides status information."""
    
    def __init__(self) -> None:
        """Initialize the auto-own manager."""
        self.current_runner: Optional[AutoOwnRunner] = None
        self.agent = AutoOwnAgent()
        
    def start_auto_own(
        self,
        target: str,
        on_output: Callable[[str, str], None],
        on_complete: Callable[[bool, Optional[str]], None],
        on_progress: Callable[[str, float], None],
        verbose: bool = False,
        debug: bool = False,
    ) -> bool:
        """Start an auto-own process.
        
        Args:
            target: Target IP address or hostname
            on_output: Callback for output lines (line, level)
            on_complete: Callback for completion (success, error_msg)
            on_progress: Callback for progress updates (status, percentage)
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            
        Returns:
            True if started successfully, False otherwise
        """
        if self.is_running():
            logger.warning("Auto-own process already running")
            return False
            
        try:
            # Validate target
            if not target or not target.strip():
                logger.error("Invalid target specified")
                return False
                
            # Create and start the runner
            self.current_runner = AutoOwnRunner(
                target=target.strip(),
                on_output=on_output,
                on_complete=on_complete,
                on_progress=on_progress,
                verbose=verbose,
                debug=debug
            )
            
            self.current_runner.start()
            logger.info("Auto-own process started", target=target)
            return True
            
        except Exception as e:
            logger.error("Failed to start auto-own process", target=target, error=str(e))
            return False
            
    def stop_current(self) -> None:
        """Stop the current auto-own process."""
        if self.current_runner:
            self.current_runner.stop()
            logger.info("Auto-own stop requested")
            
    def is_running(self) -> bool:
        """Check if an auto-own process is currently running.
        
        Returns:
            True if running, False otherwise
        """
        return (
            self.current_runner is not None and 
            self.current_runner.is_alive() and 
            not self.current_runner.is_stopped()
        )
        
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the auto-own manager.
        
        Returns:
            Dictionary containing status information
        """
        return {
            "running": self.is_running(),
            "target": self.current_runner.target if self.current_runner else None,
            "auto_own_enabled": config.AUTO_OWN_ENABLED,
            "openai_configured": bool(config.get_openai_api_key()),
            "available_targets": self.agent.get_available_targets()
        }
        
    def get_target_history(self, target: str) -> List[Dict[str, Any]]:
        """Get auto-own history for a target.
        
        Args:
            target: Target IP address
            
        Returns:
            List of historical results
        """
        return self.agent.get_target_history(target)
        
    def refresh_agent(self) -> None:
        """Refresh the LLM agent to pick up new API keys or configuration changes."""
        try:
            # Re-initialize the agent to pick up new configuration
            from .llm_agent import AutoOwnAgent
            self.agent = AutoOwnAgent()
            logger.info("Auto-own agent refreshed successfully")
        except Exception as e:
            logger.error("Failed to refresh auto-own agent", error=str(e))
            raise
    
    def cleanup(self) -> None:
        """Clean up resources."""
        if self.current_runner:
            self.current_runner.stop()
            self.current_runner.join(timeout=5)
            self.current_runner = None 