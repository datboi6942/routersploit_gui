"""LLM Agent for automated vulnerability assessment and exploitation."""

import json
import time
from typing import Any, Dict, List, Optional, Callable
from pathlib import Path

import openai
import structlog

from . import config
from .tools import ToolManager

logger = structlog.get_logger(__name__)


class AutoOwnAgent:
    """LLM agent for automated vulnerability assessment and exploitation."""
    
    def __init__(self, target: str, on_output: Callable, debug: bool = False, verbose: bool = False) -> None:
        self.target = target
        self.on_output = on_output
        self.debug = debug
        self.verbose = verbose
        
        self.client = None
        self.tool_manager = ToolManager()
        self.conversation: List[Dict[str, Any]] = []
        self.tool_cache: Dict[str, Any] = {}
        
        self.max_iterations = 10
        self.iteration_count = 0
        self.start_time = time.time()
        
        # State tracking
        self.scan_result: Optional[Dict[str, Any]] = None
        self.analysis_result: Optional[Dict[str, Any]] = None
        self.analysis_has_run = False
        
        self.max_summary_length = 2000
        self.initial_prompt = self._get_initial_prompt(target)

    def _ensure_client(self) -> None:
        api_key = config.get_openai_api_key()
        if not api_key:
            raise ValueError("OpenAI API key is not configured.")
        
        if not self.client or getattr(self.client, '_api_key', None) != api_key:
            self.client = openai.OpenAI(api_key=api_key)
            setattr(self.client, '_api_key', api_key)

    def run(self):
        self._add_user_message(self.initial_prompt)

        for i in range(self.max_iterations):
            self.iteration_count = i + 1
            if self.debug:
                self.on_output(f"🐛 [DEBUG-LLM] === ITERATION {self.iteration_count} ===", "info")
            
            self.on_output(f"[Verbose] 🧠 Iteration {self.iteration_count}/{self.max_iterations} ({(self.iteration_count/self.max_iterations)*100:.1f}%) - ETA: {self.get_eta(i)}s", "info")

            assistant_message = self._get_llm_response(self.conversation)
            
            # Add assistant message to conversation if it has content
            if assistant_message.get("content"):
                self._add_assistant_message(assistant_message["content"])

            tool_calls = assistant_message.get("tool_calls")
            
            # Prevent redundant analysis calls
            if self.analysis_has_run and tool_calls and any(tc.function.name == 'analyze_vulnerabilities' for tc in tool_calls):
                tool_calls = [tc for tc in tool_calls if tc.function.name != 'analyze_vulnerabilities']
                if not tool_calls:
                    self._add_user_message("Vulnerability analysis is complete. Review the findings and decide on the next actions, like which exploit to try. Do not run 'analyze_vulnerabilities' again.")
                    continue

            if not tool_calls:
                self.on_output("[Verbose] No more tool calls. Conversation complete.", "info")
                break

            for tool_call in tool_calls:
                self._execute_tool_call(tool_call)

        final_summary = self.request_final_summary()
        
        return {
            "target": self.target,
            "conversation_history": self.conversation,
            "final_summary": final_summary,
        }

    def _execute_tool_call(self, tool_call: Any): # Changed type hint
        tool_name = tool_call.function.name
        tool_id = tool_call.id
        try:
            tool_args = json.loads(tool_call.function.arguments)
        except json.JSONDecodeError:
            self.on_output(f"❌ [ERROR] Invalid JSON in tool arguments for {tool_name}", "error")
            self._add_tool_result(tool_id, tool_name, {"error": "Invalid JSON arguments"})
            return

        if self.debug:
            self.on_output(f"🐛 [DEBUG-LLM] Preparing to execute tool: {tool_name} with args: {tool_args}", "info")

        if tool_name == "analyze_vulnerabilities":
            if self.scan_result:
                tool_args["scan_result"] = self.scan_result
            else:
                self._add_tool_result(tool_id, tool_name, {"error": "No nmap scan result available. Run nmap_scan first."})
                return

        try:
            result = self.tool_manager.execute_tool(tool_name, tool_args, on_output=self.on_output)
        except Exception as e:
            result = {"error": f"Tool execution failed: {e}"}

        if tool_name == "run_nmap_scan":
            self.scan_result = result
            self.analysis_has_run = False
        elif tool_name == "analyze_vulnerabilities":
            self.analysis_result = result
            if result and (result.get('vulnerabilities') or result.get('exploits_found')):
                self.analysis_has_run = True

        summarized_result_str = self._summarize_result(result)
        self._add_tool_result(tool_id, tool_name, summarized_result_str)

    def _summarize_result(self, result: Any) -> str:
        try:
            result_str = json.dumps(result)
        except (TypeError, OverflowError):
            result_str = str(result)

        if len(result_str) > self.max_summary_length:
            summary = {"summary": "Result too large, summarized.", "size": len(result_str)}
            if isinstance(result, dict):
                if "ports" in result:
                    open_ports = [p for p in result.get("ports", []) if p.get("state") == "open"]
                    summary["open_ports_count"] = len(open_ports)
                    summary["open_ports"] = [p.get("port") for p in open_ports[:20]]
                if "vulnerabilities" in result:
                    summary["vulnerabilities_found"] = len(result["vulnerabilities"])
                if "exploits_found" in result:
                    summary["exploits_found"] = len(result["exploits_found"])
                    summary["top_exploits"] = [e.get("exploit", {}).get("name", "N/A") for e in result["exploits_found"][:3]]
            return json.dumps(summary)
        return result_str

    def _get_llm_response(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        self._ensure_client()
        
        tools = self.tool_manager.get_tool_definitions()
        
        try:
            response = self.client.chat.completions.create(
                model=config.OPENAI_MODEL,
                messages=messages,
                tools=tools,
                tool_choice="auto",
                max_tokens=config.OPENAI_MAX_TOKENS,
                temperature=config.OPENAI_TEMPERATURE,
            )
            choice = response.choices[0].message
            return {
                "content": choice.content,
                "tool_calls": choice.tool_calls,
                "usage": response.usage.model_dump() if response.usage else None
            }
        except Exception as e:
            self.on_output(f"❌ LLM API call failed: {e}", "error")
            return {"error": str(e)}

    def request_final_summary(self):
        summary_prompt = "Provide a final, comprehensive summary of the entire auto-own process. Detail all vulnerabilities found, exploits attempted, and the final outcome. If no vulnerabilities were found, state that clearly and provide recommendations for next steps."
        self._add_user_message(summary_prompt)
        
        response = self._get_llm_response(self.conversation)
        return response.get("content", "Failed to generate final summary.")

    def _add_user_message(self, content: str):
        self.conversation.append({"role": "user", "content": content})

    def _add_assistant_message(self, content: str):
        self.conversation.append({"role": "assistant", "content": content})

    def _add_tool_result(self, tool_call_id: str, tool_name: str, result: str):
        # First, add the tool call to the conversation history
        self.conversation.append({
            "role": "assistant",
            "content": None,
            "tool_calls": [{"id": tool_call_id, "type": "function", "function": {"name": tool_name, "arguments": "{}"}}]
        })
        # Then, add the result of that tool call
        self.conversation.append({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "name": tool_name,
            "content": result,
        })

    def get_eta(self, current_iteration: int) -> int:
        elapsed = time.time() - self.start_time
        avg_time_per_iter = elapsed / (current_iteration + 1)
        remaining_iters = self.max_iterations - (current_iteration + 1)
        return int(avg_time_per_iter * remaining_iters)
        
    def _get_initial_prompt(self, target: str) -> str:
        return f"""You are an elite cybersecurity penetration tester with deep expertise in automated vulnerability assessment. Your mission is to thoroughly analyze the target {target}, identify ALL potential vulnerabilities (especially low-hanging fruit), and achieve Remote Code Execution (RCE).

        **CRITICAL SUCCESS FACTORS:**
        1. **Be EXTREMELY thorough** - Don't miss obvious vulnerabilities like SMB, RDP, outdated services.
        2. **Use BOTH RouterSploit AND Metasploit** - The tools will search both.
        3. **Provide detailed status updates** - Explain your reasoning and findings clearly.

        **MANDATORY WORKFLOW:**
        1. **SCAN**: Use `run_nmap_scan` to get a full picture of the target.
        2. **ANALYZE**: IMMEDIATELY follow the scan with `analyze_vulnerabilities`. This is CRITICAL. This tool will automatically perform web searches and check exploit databases for ALL open ports.
        3. **EXPLOIT**: Based on the analysis, select the most promising exploit and use `run_exploit`.

        Do not deviate from this workflow. Your primary goal is to find the easiest path to compromise. Start by calling `run_nmap_scan` on the target.""" 