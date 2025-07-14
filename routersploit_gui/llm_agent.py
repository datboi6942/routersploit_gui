"""LLM Agent for automated vulnerability assessment and exploitation."""

import json
import time
from typing import Any, Dict, List, Optional, Tuple, Callable
from pathlib import Path

import openai
import structlog

from . import config
from .tools import ToolManager

logger = structlog.get_logger(__name__)


class AutoOwnAgent:
    """LLM agent for automated vulnerability assessment and exploitation."""
    
    def __init__(self) -> None:
        """Initialize the Auto-Own agent."""
        self.client = None  # Will be initialized on demand
        self.tool_manager = ToolManager()
        self.conversation_history: List[Dict[str, Any]] = []
        self.tool_call_cache: Dict[str, Any] = {}  # Cache for repeated tool calls
        
    def _ensure_client(self) -> None:
        """Ensure the OpenAI client is initialized with the latest API key."""
        api_key = config.get_openai_api_key()
        if not self.client or getattr(self.client, '_api_key', None) != api_key:
            self.client = openai.OpenAI(api_key=api_key)
            self.client._api_key = api_key  # type: ignore
        
    def _add_to_history(self, role: str, content: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a message to the conversation history.
        
        Args:
            role: Role of the message (user, assistant, system)
            content: Message content
            metadata: Optional metadata about the message
        """
        message = {
            "role": role,
            "content": content,
            "timestamp": time.time(),
            "metadata": metadata or {}
        }
        self.conversation_history.append(message)
        
    def _estimate_token_count(self, messages: List[Dict[str, Any]]) -> int:
        """Estimate token count for a list of messages.
        
        Args:
            messages: List of messages to estimate tokens for
            
        Returns:
            Estimated token count
        """
        # Rough estimation: ~4 characters per token
        total_chars = 0
        for message in messages:
            if isinstance(message.get("content"), str):
                total_chars += len(message["content"])
            if message.get("tool_calls"):
                # Tool calls add significant overhead
                total_chars += len(json.dumps(message["tool_calls"]))
        return total_chars // 4
    
    def _truncate_messages(self, messages: List[Dict[str, Any]], max_tokens: int = 6000) -> List[Dict[str, Any]]:
        """Truncate messages to fit within token limits while preserving context.
        
        Args:
            messages: List of messages to truncate
            max_tokens: Maximum tokens to allow
            
        Returns:
            Truncated message list
        """
        if self._estimate_token_count(messages) <= max_tokens:
            return messages
        
        # Always keep system prompt and most recent messages
        system_messages = [msg for msg in messages if msg.get("role") == "system"]
        other_messages = [msg for msg in messages if msg.get("role") != "system"]
        
        # Start with system messages
        truncated = system_messages.copy()
        current_tokens = self._estimate_token_count(truncated)
        
        # Add messages from the end (most recent first)
        for message in reversed(other_messages):
            message_tokens = self._estimate_token_count([message])
            if current_tokens + message_tokens <= max_tokens:
                truncated.insert(-len(system_messages) or len(truncated), message)
                current_tokens += message_tokens
            else:
                break
        
        # If we truncated, add a summary message
        if len(truncated) < len(messages):
            summary = {
                "role": "system",
                "content": f"[CONTEXT TRUNCATED] Previous conversation included {len(messages) - len(truncated)} messages that were summarized to fit token limits. Current focus: vulnerability assessment and exploitation of target."
            }
            truncated.insert(-len(system_messages) or len(truncated), summary)
        
        return truncated
    
    def _should_cache_tool_call(self, tool_name: str, tool_args: Dict[str, Any]) -> bool:
        """Check if a tool call should be cached to avoid repetition.
        
        Args:
            tool_name: Name of the tool
            tool_args: Tool arguments
            
        Returns:
            True if should cache, False otherwise
        """
        # Cache vulnerability analysis for same services
        if tool_name == "analyze_vulnerabilities":
            return True
        # Cache exploit searches for same service/version combinations
        if tool_name == "search_exploits":
            return True
        return False
    
    def _get_cached_result(self, tool_name: str, tool_args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get cached result for a tool call.
        
        Args:
            tool_name: Name of the tool
            tool_args: Tool arguments
            
        Returns:
            Cached result if available, None otherwise
        """
        cache_key = f"{tool_name}:{json.dumps(tool_args, sort_keys=True)}"
        return self.tool_call_cache.get(cache_key)
    
    def _cache_tool_result(self, tool_name: str, tool_args: Dict[str, Any], result: Dict[str, Any]) -> None:
        """Cache a tool result.
        
        Args:
            tool_name: Name of the tool
            tool_args: Tool arguments
            result: Tool result to cache
        """
        if self._should_cache_tool_call(tool_name, tool_args):
            cache_key = f"{tool_name}:{json.dumps(tool_args, sort_keys=True)}"
            self.tool_call_cache[cache_key] = result
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for the LLM agent.
        
        Returns:
            System prompt string
        """
        return """You are an expert cybersecurity penetration tester and exploit developer. Your goal is to automatically assess targets for vulnerabilities and develop or find working exploits to achieve Remote Code Execution (RCE).

Your capabilities:
1. Analyze nmap scan results to identify potential vulnerabilities
2. Search for existing exploits in Metasploit and Exploit-DB
3. Generate custom exploits when existing ones are not available
4. Verify exploit functionality and success
5. Focus on achieving RCE (Remote Code Execution)

Your workflow:
1. Scan the target using nmap to enumerate services and versions
2. Analyze scan results to identify potential vulnerabilities
3. Search for existing exploits that match the discovered services/versions
4. If no existing exploit is found, attempt to generate a custom exploit
5. Test and verify the exploit works
6. Document the process and results

Safety guidelines:
- Only test against authorized targets
- Log all actions for audit purposes
- Use safe testing methods when possible
- Provide clear documentation of findings

Important: Be concise in your responses. Avoid repeating the same analysis for identical services. Focus on the most promising vulnerabilities first."""

    def _sanitize_message_content(self, content: str) -> str:
        """Sanitize message content to remove problematic characters for OpenAI API.
        
        Args:
            content: Raw message content
            
        Returns:
            Sanitized message content
        """
        if not content:
            return content
        
        # Remove problematic Unicode characters that can cause encoding issues
        # Replace common debug emojis with text equivalents
        content = content.replace("🐛", "[DEBUG]")
        content = content.replace("🔄", "[PROCESSING]")
        content = content.replace("✅", "[SUCCESS]")
        content = content.replace("❌", "[ERROR]")
        content = content.replace("🕒", "[TIME]")
        
        # Encode to UTF-8 and decode back to handle any remaining problematic characters
        try:
            content = content.encode('utf-8', errors='ignore').decode('utf-8')
        except UnicodeError:
            # If encoding fails, try to remove non-ASCII characters
            content = ''.join(char for char in content if ord(char) < 128)
        
        return content

    def _sanitize_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sanitize all messages to ensure they're safe for OpenAI API.
        
        Args:
            messages: List of messages to sanitize
            
        Returns:
            Sanitized messages
        """
        sanitized = []
        for message in messages:
            sanitized_message = message.copy()
            if "content" in sanitized_message and isinstance(sanitized_message["content"], str):
                sanitized_message["content"] = self._sanitize_message_content(sanitized_message["content"])
            sanitized.append(sanitized_message)
        return sanitized

    def _call_llm(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Make a call to the OpenAI API.
        
        Args:
            messages: List of conversation messages
            tools: Optional list of tool definitions
            
        Returns:
            API response
        """
        try:
            self._ensure_client()
            
            # Truncate messages to prevent token limit issues
            truncated_messages = self._truncate_messages(messages)
            
            # Sanitize messages to prevent encoding issues
            sanitized_messages = self._sanitize_messages(truncated_messages)
            
            kwargs = {
                "model": config.OPENAI_MODEL,
                "messages": sanitized_messages,
                "max_tokens": config.OPENAI_MAX_TOKENS,
                "temperature": config.OPENAI_TEMPERATURE,
            }
            
            if tools:
                kwargs["tools"] = tools
                kwargs["tool_choice"] = "auto"
            
            response = self.client.chat.completions.create(**kwargs)
            
            return {
                "content": response.choices[0].message.content,
                "tool_calls": response.choices[0].message.tool_calls,
                "usage": response.usage.model_dump() if response.usage else None
            }
            
        except Exception as e:
            error_msg = f"LLM API call failed: {str(e)}"
            logger.error(error_msg, error=str(e))
            return {"error": error_msg}

    def _define_tools(self) -> List[Dict[str, Any]]:
        """Define the tools available to the LLM agent.
        
        Returns:
            List of tool definitions
        """
        return [
            {
                "type": "function",
                "function": {
                    "name": "scan_target",
                    "description": "Scan a target using nmap to enumerate services and versions",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "IP address or hostname to scan"
                            },
                            "ports": {
                                "type": "string",
                                "description": "Port range to scan (default: 1-1000)",
                                "default": "1-1000"
                            }
                        },
                        "required": ["target"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "analyze_vulnerabilities",
                    "description": "Analyze scan results to identify potential vulnerabilities and exploits",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "scan_results": {
                                "type": "object",
                                "description": "Results from nmap scan"
                            }
                        },
                        "required": ["scan_results"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "search_exploits",
                    "description": "Search for existing exploits in Metasploit and Exploit-DB",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "service": {
                                "type": "string",
                                "description": "Service name to search for"
                            },
                            "version": {
                                "type": "string",
                                "description": "Service version",
                                "default": ""
                            }
                        },
                        "required": ["service"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "generate_exploit",
                    "description": "Generate a custom exploit for a vulnerability",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "vulnerability": {
                                "type": "object",
                                "description": "Vulnerability details"
                            },
                            "target_info": {
                                "type": "object",
                                "description": "Target information"
                            }
                        },
                        "required": ["vulnerability", "target_info"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "test_exploit",
                    "description": "Test an exploit against the target",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "exploit_code": {
                                "type": "string",
                                "description": "Exploit code to test"
                            },
                            "target": {
                                "type": "string",
                                "description": "Target to test against"
                            }
                        },
                        "required": ["exploit_code", "target"]
                    }
                }
            }
        ]

    def _execute_tool(self, tool_name: str, arguments: Dict[str, Any], verbose: bool = False, debug: bool = False, on_output: Optional[Callable[[str, str], None]] = None) -> Dict[str, Any]:
        """Execute a tool based on the tool name and arguments, with verbose output if enabled."""
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-TOOL] {line}", "warning" if level == "info" else level)
        
        # Check cache first
        cached_result = self._get_cached_result(tool_name, arguments)
        if cached_result:
            if debug:
                debug_emit(f"Using cached result for {tool_name}")
            return cached_result
                
        try:
            if debug:
                debug_emit(f"Tool execution starting: {tool_name}")
                debug_emit(f"Arguments received: {arguments}")
                
            if tool_name == "scan_target":
                target = arguments.get("target")
                ports = arguments.get("ports", "1-1000")
                if debug:
                    debug_emit(f"Scan target: {target}, ports: {ports}")
                result = self.tool_manager.scan_and_analyze(target, verbose=verbose, debug=debug, on_output=on_output)
                
            elif tool_name == "analyze_vulnerabilities":
                scan_results = arguments.get("scan_results", {})
                if debug:
                    debug_emit(f"Analyzing vulnerabilities for {len(scan_results.get('ports', []))} ports")
                result = self.tool_manager.vuln_analyzer.analyze_scan_results(scan_results, verbose=verbose, debug=debug, on_output=on_output)
                
            elif tool_name == "search_exploits":
                service = arguments.get("service")
                version = arguments.get("version", "")
                if debug:
                    debug_emit(f"Searching exploits for {service} {version}")
                result = self.tool_manager.search_exploits(service, version, verbose=verbose, debug=debug, on_output=on_output)
                
            elif tool_name == "generate_exploit":
                vulnerability = arguments.get("vulnerability", {})
                target_info = arguments.get("target_info", {})
                if debug:
                    debug_emit(f"Generating exploit for vulnerability: {vulnerability.get('name', 'Unknown')}")
                result = self.tool_manager.generate_exploit(vulnerability, target_info, verbose=verbose, debug=debug, on_output=on_output)
                
            elif tool_name == "test_exploit":
                exploit_code = arguments.get("exploit_code", "")
                target = arguments.get("target", "")
                if debug:
                    debug_emit(f"Testing exploit against {target}")
                result = self.tool_manager.test_exploit(exploit_code, target, verbose=verbose, debug=debug, on_output=on_output)
                
            else:
                result = {"error": f"Unknown tool: {tool_name}"}
                
            # Cache the result
            self._cache_tool_result(tool_name, arguments, result)
            
            return result
            
        except Exception as e:
            error_msg = f"Tool execution failed: {str(e)}"
            logger.error(error_msg, tool=tool_name, error=str(e))
            return {"error": error_msg}

    def auto_own_target(self, target: str, verbose: bool = False, debug: bool = False, on_output: Optional[Callable[[str, str], None]] = None) -> Dict[str, Any]:
        """Perform automated vulnerability assessment and exploitation on a target.
        
        Args:
            target: Target IP address or hostname
            verbose: Whether to emit detailed output
            debug: Whether to emit comprehensive debug information
            on_output: Optional callback for output lines (line, level)
        Returns:
            Complete auto-own results
        """
        def emit(line: str, level: str = "info"):
            if on_output:
                on_output(line, level)
                
        def debug_emit(line: str, level: str = "info"):
            if debug and on_output:
                on_output(f"🐛 [DEBUG-LLM] {line}", "warning" if level == "info" else level)
        try:
            # Clear cache and history for new target
            self.tool_call_cache.clear()
            self.conversation_history.clear()
            
            logger.info("Starting auto-own process", target=target)
            if verbose:
                emit(f"[Verbose] Preparing LLM system prompt and initial user message.")
            if debug:
                debug_emit(f"Auto-own target started: {target}")
                debug_emit(f"Flags: verbose={verbose}, debug={debug}")
                debug_emit(f"OpenAI client initialized: {self.client is not None}")
                debug_emit(f"Tool manager initialized: {self.tool_manager is not None}")
                debug_emit(f"Conversation history cleared, length: {len(self.conversation_history)}")
                
            # Initialize conversation
            system_prompt = self._get_system_prompt()
            if debug:
                debug_emit(f"System prompt length: {len(system_prompt)} characters")
                debug_emit(f"System prompt preview: {system_prompt[:150]}...")
                
            messages = [{"role": "system", "content": system_prompt}]
            
            # Add initial user message
            user_message = f"Perform a complete vulnerability assessment and exploitation analysis on target {target}. Focus on finding RCE opportunities."
            messages.append({"role": "user", "content": user_message})
            self._add_to_history("user", user_message)
            
            if verbose:
                emit(f"[Verbose] Added system and user messages. Defining tools.")
            if debug:
                debug_emit(f"Initial user message: {user_message}")
                debug_emit(f"Messages array length: {len(messages)}")
                
            # Define available tools
            tools = self._define_tools()
            if debug:
                debug_emit(f"Defined {len(tools)} tools: {[tool['function']['name'] for tool in tools]}")
                
            # Start the conversation loop
            max_iterations = 10
            iteration = 0
            if debug:
                debug_emit(f"Starting conversation loop, max iterations: {max_iterations}")
                
            conversation_start_time = time.time()
            while iteration < max_iterations:
                iteration += 1
                iteration_start_time = time.time()
                logger.info(f"Auto-own iteration {iteration}", target=target)
                if verbose:
                    emit(f"[Verbose] LLM conversation iteration {iteration}.")
                    emit(f"[Verbose] Calling LLM with {len(messages)} messages and {len(tools)} tools.")
                if debug:
                    debug_emit(f"=== ITERATION {iteration} ===")
                    debug_emit(f"Messages in conversation: {len(messages)}")
                    debug_emit(f"Last 3 message roles: {[msg['role'] for msg in messages[-3:]]}")
                    debug_emit(f"Estimated token count: {self._estimate_token_count(messages)}")
                    debug_emit(f"Preparing LLM API call...")
                    
                # Show progress estimate
                progress_pct = (iteration / max_iterations) * 100
                elapsed_conversation = time.time() - conversation_start_time
                avg_iteration_time = elapsed_conversation / iteration
                eta_conversation = avg_iteration_time * (max_iterations - iteration)
                if verbose:
                    emit(f"[Verbose] 🔄 Iteration {iteration}/{max_iterations} ({progress_pct:.1f}%) - ETA: {eta_conversation:.0f}s", "info")
                    
                # Call LLM
                response = self._call_llm(messages, tools)
                iteration_elapsed = time.time() - iteration_start_time
                if debug:
                    debug_emit(f"LLM API call completed in {iteration_elapsed:.1f}s")
                    debug_emit(f"Response keys: {list(response.keys())}")
                    if "usage" in response and response["usage"]:
                        debug_emit(f"Token usage: {response['usage']}")
                    
                if "error" in response:
                    logger.error("LLM call failed", error=response["error"])
                    emit(f"[Verbose] LLM call failed: {response['error']}", "error")
                    if debug:
                        debug_emit(f"LLM API error: {response['error']}", "error")
                    break
                # Add assistant response to history
                assistant_content = response.get("content", "")
                tool_calls = response.get("tool_calls", None)
                
                # Ensure tool_calls is a list, not None
                if tool_calls is None:
                    tool_calls = []
                
                if debug:
                    debug_emit(f"Assistant content length: {len(assistant_content) if assistant_content else 0}")
                    debug_emit(f"Tool calls requested: {len(tool_calls)}")
                    if tool_calls:
                        debug_emit(f"Tool call names: {[tc.function.name for tc in tool_calls]}")
                
                # Convert tool calls to serializable format
                serializable_tool_calls = []
                if tool_calls:
                    for tool_call in tool_calls:
                        serializable_tool_calls.append({
                            "id": tool_call.id,
                            "type": tool_call.type,
                            "function": {
                                "name": tool_call.function.name,
                                "arguments": tool_call.function.arguments
                            }
                        })
                
                # Always add assistant message if there's content OR tool calls
                if assistant_content or tool_calls:
                    assistant_message = {"role": "assistant"}
                    if assistant_content:
                        assistant_message["content"] = assistant_content
                    if tool_calls:
                        assistant_message["tool_calls"] = serializable_tool_calls
                    
                    messages.append(assistant_message)
                    self._add_to_history("assistant", assistant_content or "", {"tool_calls": bool(tool_calls)})
                    
                    if verbose:
                        if assistant_content:
                            emit(f"[Verbose] LLM response: {assistant_content[:120]}{'...' if len(assistant_content) > 120 else ''}")
                        if tool_calls:
                            emit(f"[Verbose] LLM requested {len(tool_calls)} tool calls")
                    if debug:
                        debug_emit(f"Added assistant message to conversation")
                        debug_emit(f"Current conversation length: {len(messages)}")

                # Handle tool calls
                if not tool_calls:
                    if verbose:
                        emit(f"[Verbose] No more tool calls. Conversation complete.")
                    if debug:
                        debug_emit(f"No tool calls found, ending conversation loop")
                    break
                    
                if debug:
                    debug_emit(f"Processing {len(tool_calls)} tool calls...")

                # Execute tools
                for tool_call in tool_calls:
                    tool_name = tool_call.function.name
                    tool_args = json.loads(tool_call.function.arguments)
                    logger.info(f"Executing tool: {tool_name}", arguments=tool_args)
                    if verbose:
                        emit(f"[Verbose] Executing tool: {tool_name} with args: {tool_args}")
                    if debug:
                        debug_emit(f"Tool execution started: {tool_name}")
                        debug_emit(f"Tool call ID: {tool_call.id}")
                        debug_emit(f"Tool arguments: {tool_args}")
                        
                    # Execute the tool
                    tool_result = self._execute_tool(tool_name, tool_args, verbose=verbose, debug=debug, on_output=on_output)
                    
                    # Truncate large tool results to prevent token overflow
                    result_str = json.dumps(tool_result, indent=2)
                    if len(result_str) > 5000:
                        # Truncate very large results
                        if "scan_results" in tool_result:
                            # Keep only essential scan info
                            truncated_result = {
                                "target": tool_result.get("target"),
                                "status": tool_result.get("status"),
                                "ports": tool_result.get("ports", [])[:10],  # Limit to first 10 ports
                                "vulnerability_analysis": tool_result.get("vulnerability_analysis", {}),
                                "note": f"Result truncated - showed first 10 of {len(tool_result.get('ports', []))} ports"
                            }
                            result_str = json.dumps(truncated_result, indent=2)
                        else:
                            result_str = result_str[:5000] + "\n... [TRUNCATED]"
                    
                    if verbose:
                        emit(f"[Verbose] Tool result: {result_str[:120]}{'...' if len(result_str) > 120 else ''}")
                    if debug:
                        debug_emit(f"Tool execution completed: {tool_name}")
                        debug_emit(f"Result keys: {list(tool_result.keys())}")
                        debug_emit(f"Result size: {len(result_str)} characters")
                        
                    # Add tool result to conversation
                    tool_message = {
                        "role": "tool",
                        "content": result_str,
                        "tool_call_id": tool_call.id
                    }
                    messages.append(tool_message)
                    self._add_to_history("tool", result_str, {"tool_name": tool_name})
                    if debug:
                        debug_emit(f"Tool result added to conversation")
                        debug_emit(f"Total messages now: {len(messages)}")
                        
                # Check if we should truncate messages to prevent token overflow
                if self._estimate_token_count(messages) > 7000:
                    if debug:
                        debug_emit(f"Token count approaching limit, truncating messages")
                    messages = self._truncate_messages(messages, max_tokens=6000)
                    if debug:
                        debug_emit(f"Messages after truncation: {len(messages)}")
                        
            # Generate final summary
            summary_message = "Provide a final summary of the auto-own process, including any vulnerabilities found, exploits discovered, and recommendations for achieving RCE."
            messages.append({"role": "user", "content": summary_message})
            if verbose:
                emit(f"[Verbose] Requesting final summary from LLM.")
            final_response = self._call_llm(messages)
            
            # Compile results
            results = {
                "target": target,
                "conversation_history": self.conversation_history,
                "final_summary": final_response.get("content", ""),
                "iterations": iteration,
                "timestamp": time.time()
            }
            
            # Save results to file
            self._save_results(results)
            logger.info("Auto-own process completed", target=target, iterations=iteration)
            return results
            
        except Exception as e:
            error_msg = f"Auto-own process failed: {str(e)}"
            logger.error(error_msg, target=target, error=str(e))
            emit(f"[Verbose] Exception: {error_msg}", "error")
            return {"error": error_msg}

    def _save_results(self, results: Dict[str, Any]) -> None:
        """Save auto-own results to a file.
        
        Args:
            results: Results to save
        """
        try:
            timestamp = int(results["timestamp"])
            target = results["target"]
            filename = f"auto_own_{target}_{timestamp}.json"
            filepath = config.AUTO_OWN_RESULTS_DIR / filename
            
            # Ensure the results are JSON serializable
            serializable_results = self._make_json_serializable(results)
            
            with open(filepath, 'w') as f:
                json.dump(serializable_results, f, indent=2, default=str)
            
            logger.info("Auto-own results saved", filepath=str(filepath))
            
        except Exception as e:
            logger.error("Failed to save auto-own results", error=str(e))
    
    def _make_json_serializable(self, obj: Any) -> Any:
        """Convert an object to a JSON serializable format.
        
        Args:
            obj: Object to convert
            
        Returns:
            JSON serializable version of the object
        """
        if isinstance(obj, dict):
            return {k: self._make_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_serializable(item) for item in obj]
        elif hasattr(obj, '__dict__'):
            # Convert objects with __dict__ to dictionaries
            return self._make_json_serializable(obj.__dict__)
        elif isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        else:
            # For any other type, convert to string
            return str(obj)

    def get_available_targets(self) -> List[str]:
        """Get list of recently scanned targets.
        
        Returns:
            List of target IP addresses
        """
        try:
            targets = set()
            
            # Look for existing result files
            for result_file in config.AUTO_OWN_RESULTS_DIR.glob("auto_own_*.json"):
                try:
                    with open(result_file, 'r') as f:
                        data = json.load(f)
                        if "target" in data:
                            targets.add(data["target"])
                except Exception:
                    continue
            
            return list(targets)
            
        except Exception as e:
            logger.error("Failed to get available targets", error=str(e))
            return []

    def get_target_history(self, target: str) -> List[Dict[str, Any]]:
        """Get auto-own history for a specific target.
        
        Args:
            target: Target IP address
            
        Returns:
            List of historical results for the target
        """
        try:
            history = []
            
            for result_file in config.AUTO_OWN_RESULTS_DIR.glob(f"auto_own_{target}_*.json"):
                try:
                    with open(result_file, 'r') as f:
                        data = json.load(f)
                        history.append(data)
                except Exception:
                    continue
            
            # Sort by timestamp
            history.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
            
            return history
            
        except Exception as e:
            logger.error("Failed to get target history", target=target, error=str(e))
            return [] 