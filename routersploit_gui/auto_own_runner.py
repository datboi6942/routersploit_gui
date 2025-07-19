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
        
        # Agent will be initialized in the run method of the thread
        self.agent: Optional[AutoOwnAgent] = None
        
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
            
            # Step 1: Initialize agent
            self._progress("Initializing LLM agent", 10.0)
            self._output("Initializing LLM agent...", "info")
            
            self.agent = AutoOwnAgent(
                target=self.target,
                on_output=self._output,
                verbose=self.verbose,
                debug=self.debug
            )
            
            # Step 2: Start auto-own process
            self._progress("Starting vulnerability assessment", 20.0)
            self._output(f"Starting vulnerability assessment on {self.target}...", "info")
            
            results = self.agent.run()

            if "error" in results:
                error_msg = results["error"]
                self._output(f"ERROR: {error_msg}", "error")
                return
                
            # Step 3: Process results
            self._progress("Processing results", 80.0)
            
            final_summary = results.get("final_summary", "No summary generated.")
            
            self._output("\n" + "="*60, "info")
            self._output("🎯 AUTOMATED VULNERABILITY ASSESSMENT COMPLETE", "success")
            self._output(f"🔍 Target: {self.target}", "info")
            self._output(f"⏱️ Total Time: {time.time() - start_time:.1f} seconds", "info")
            self._output("="*60 + "\n", "info")
            self._output(final_summary, "info")
            self._output("\n" + "="*60, "info")

            self._progress("Complete", 100.0)
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
        # The agent is now created inside the runner, so we don't keep an instance here.
        
    def start_auto_own(
        self,
        target: str,
        on_output: Callable[[str, str], None],
        on_complete: Callable[[bool, Optional[str]], None],
        on_progress: Callable[[str, float], None],
        verbose: bool = False,
        debug: bool = False,
    ) -> bool:
        """Start an auto-own process."""
        if self.is_running():
            logger.warning("Auto-own process already running")
            return False
            
        try:
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
        """Get the current status of the auto-own manager."""
        # Since the agent is in the runner, we can't get available targets this way anymore.
        # This part can be refactored if needed.
        return {
            "running": self.is_running(),
            "target": self.current_runner.target if self.current_runner else None,
            "auto_own_enabled": config.AUTO_OWN_ENABLED,
            "openai_configured": bool(config.get_openai_api_key()),
            "available_targets": [] 
        }
        
    def get_target_history(self, target: str) -> List[Dict[str, Any]]:
        """Get auto-own history for a target."""
        # This would also need refactoring to read from saved files, as the agent instance is temporary.
        return []
        
    def refresh_agent(self) -> None:
        """Refresh the LLM agent to pick up new API keys or configuration changes."""
        # This is now handled by creating a new runner.
        logger.info("Agent configuration will be refreshed on the next run.")
    
    def cleanup(self) -> None:
        """Clean up resources."""
        if self.current_runner:
            self.current_runner.stop()
            self.current_runner.join(timeout=5)
            self.current_runner = None 