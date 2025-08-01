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
            # Actually create the OpenAI client - this was missing!
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
                if self.debug:
                    self.on_output(f"🐛 [DEBUG-LLM] Passing scan result to analyze_vulnerabilities", "info")
            else:
                self._add_tool_result(tool_id, tool_name, {"error": "No nmap scan result available. Run nmap_scan first."})
                return

        try:
            if self.debug:
                self.on_output(f"🐛 [DEBUG-LLM] Executing tool: {tool_name}", "info")
            result = self.tool_manager.execute_tool(tool_name, tool_args, on_output=self.on_output)
            if self.debug:
                self.on_output(f"🐛 [DEBUG-LLM] Tool {tool_name} completed successfully", "info")
        except Exception as e:
            result = {"error": f"Tool execution failed: {e}"}
            if self.debug:
                self.on_output(f"🐛 [DEBUG-LLM] Tool {tool_name} failed: {e}", "error")

        if tool_name == "run_nmap_scan":
            self.scan_result = result
            self.analysis_has_run = False
        elif tool_name == "analyze_vulnerabilities":
            self.analysis_result = result
            if self.debug:
                if result and not result.get('error'):
                    vuln_count = len(result.get('vulnerabilities', []))
                    exploit_count = len(result.get('exploits_found', []))
                    self.on_output(f"🐛 [DEBUG-LLM] Analysis found {vuln_count} vulnerabilities, {exploit_count} exploits", "info")
                    
                    # Debug: Show actual exploit names found
                    if exploit_count > 0:
                        exploits_found = result.get('exploits_found', [])
                        exploit_names = []
                        for i, exploit_entry in enumerate(exploits_found[:5]):  # Show first 5
                            exploit_data = exploit_entry.get("exploit", {})
                            exploit_name = exploit_data.get("name", f"Unknown_{i}")
                            exploit_names.append(exploit_name)
                        self.on_output(f"🐛 [DEBUG-LLM] Top exploit names: {exploit_names}", "info")
                else:
                    self.on_output(f"🐛 [DEBUG-LLM] Analysis result: {result}", "warning")
            # Always mark analysis as run, even if no vulnerabilities found
            # This prevents redundant analysis calls
            self.analysis_has_run = True

        summarized_result_str = self._summarize_result(result)
        self._add_tool_result(tool_id, tool_name, summarized_result_str)

    def _summarize_result(self, result: Any) -> str:
        try:
            result_str = json.dumps(result)
        except (TypeError, OverflowError):
            result_str = str(result)

        # Always provide comprehensive summaries for analysis results with device intelligence
        if isinstance(result, dict) and result.get("exploits_found"):
            # Create a comprehensive summary for exploit analysis results
            summary = {
                "target": result.get("target"),
                "scan_summary": {
                    "total_exploits_found": len(result.get("exploits_found", [])),
                    "total_vulnerabilities": len(result.get("vulnerabilities", [])),
                    "enhanced_services": len(result.get("enhanced_services", []))
                },
                "device_intelligence": self._extract_device_intelligence_summary(result),
                "service_analysis": self._extract_service_analysis_summary(result),
                "security_findings": self._extract_security_findings_summary(result)
            }
            
            # Extract meaningful exploit information
            exploits_found = result.get("exploits_found", [])
            if exploits_found:
                summary["detailed_exploits"] = []
                for i, exploit_entry in enumerate(exploits_found[:10]):  # Top 10 exploits
                    exploit_data = exploit_entry.get("exploit", {})
                    exploit_summary = {
                        "index": i,
                        "name": exploit_data.get("name", "Unknown"),
                        "rank": exploit_data.get("rank", "Unknown"),
                        "description": exploit_data.get("description", "No description")[:200],  # Truncate long descriptions
                        "source": exploit_entry.get("source", "Unknown"),
                        "port": exploit_entry.get("port", "Unknown"),
                        "service": exploit_entry.get("service", "Unknown")
                    }
                    summary["detailed_exploits"].append(exploit_summary)
                
                # Also provide a simple list of exploit names for easy reference
                summary["exploit_names"] = [
                    exploit_entry.get("exploit", {}).get("name", f"Unknown_{i}")
                    for i, exploit_entry in enumerate(exploits_found[:10])
                ]
            
            # Include vulnerability information if present
            vulnerabilities = result.get("vulnerabilities", [])
            if vulnerabilities:
                summary["vulnerability_summary"] = []
                for vuln in vulnerabilities[:5]:  # Top 5 vulnerabilities
                    vuln_summary = {
                        "type": vuln.get("type", "Unknown"),
                        "severity": vuln.get("severity", "Unknown"),
                        "cve_id": vuln.get("cve_id", "N/A"),
                        "description": vuln.get("description", "No description")[:150],
                        "port": vuln.get("port", "Unknown"),
                        "service": vuln.get("service", "Unknown")
                    }
                    summary["vulnerability_summary"].append(vuln_summary)
            
            return json.dumps(summary, indent=2)
        
        # Fallback to original logic for other result types
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
    
    def _extract_device_intelligence_summary(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract device intelligence from scan results for AI analysis."""
        device_intel = {
            "identified_devices": [],
            "device_types": set(),
            "brands_detected": set(),
            "firmware_versions": {},
            "security_contexts": []
        }
        
        ports = result.get("ports", [])
        for port in ports:
            device_info = port.get("device_info", {})
            if device_info.get("extracted_model"):
                device_intel["identified_devices"].append({
                    "port": port.get("port"),
                    "model": device_info.get("extracted_model"),
                    "brand": device_info.get("brand"),
                    "type": device_info.get("device_type"),
                    "firmware": device_info.get("firmware_version"),
                    "context": device_info.get("additional_context", [])
                })
                
                if device_info.get("brand"):
                    device_intel["brands_detected"].add(device_info["brand"])
                if device_info.get("device_type"):
                    device_intel["device_types"].add(device_info["device_type"])
                if device_info.get("firmware_version"):
                    device_intel["firmware_versions"][port.get("port")] = device_info["firmware_version"]
                
                # Aggregate security contexts
                device_intel["security_contexts"].extend(device_info.get("additional_context", []))
        
        # Convert sets to lists for JSON serialization
        device_intel["device_types"] = list(device_intel["device_types"])
        device_intel["brands_detected"] = list(device_intel["brands_detected"])
        device_intel["security_contexts"] = list(set(device_intel["security_contexts"]))  # Remove duplicates
        
        # Add dynamic vulnerability recommendations for each identified device
        device_intel["vulnerability_recommendations"] = []
        device_intel["research_requirements"] = []
        from .tools import VulnerabilityAnalyzer
        analyzer = VulnerabilityAnalyzer()
        
        for device in device_intel["identified_devices"]:
            if device.get("model"):
                # Get service from port information
                service = None
                port = device.get("port", "")
                # Find the corresponding port in results to get service info
                for port_info in result.get("ports", []):
                    if str(port_info.get("port")) == str(port):
                        service = port_info.get("service", "")
                        break
                
                if service:
                    vuln_recs = analyzer.get_dynamic_vulnerability_recommendations(
                        device["model"], service, str(port), debug=False
                    )
                    
                    # Extract research requirements for AI agent
                    for rec in vuln_recs:
                        if rec.get("research_needed"):
                            device_intel["research_requirements"].append({
                                "device": device["model"],
                                "service": service,
                                "port": port,
                                "vulnerability_type": rec["vulnerability"],
                                "research_keywords": rec.get("research_keywords", []),
                                "priority": rec.get("severity", "medium"),
                                "action_required": f"CALL search_device_vulnerabilities with device_model='{device['model']}', service='{service}', port='{port}'"
                            })
                    
                    device_intel["vulnerability_recommendations"].extend(vuln_recs)
        
        return device_intel
    
    def _extract_service_analysis_summary(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract service analysis summary for AI review."""
        service_analysis = {
            "total_open_ports": 0,
            "services_by_type": {},
            "script_results": {},
            "concerning_services": []
        }
        
        ports = result.get("ports", [])
        service_analysis["total_open_ports"] = len([p for p in ports if p.get("state") == "open"])
        
        for port in ports:
            if port.get("state") == "open":
                service = port.get("service", "unknown")
                port_num = port.get("port")
                
                # Count services by type
                if service in service_analysis["services_by_type"]:
                    service_analysis["services_by_type"][service].append(port_num)
                else:
                    service_analysis["services_by_type"][service] = [port_num]
                
                # Collect script results that might indicate security issues
                script_output = port.get("script_output", {})
                if script_output:
                    service_analysis["script_results"][str(port_num)] = list(script_output.keys())
                
                # Flag concerning services for AI attention
                concerning_indicators = [
                    "telnet", "ftp", "tftp", "snmp", "upnp", "rpc"
                ]
                if any(concern in service.lower() for concern in concerning_indicators):
                    service_analysis["concerning_services"].append({
                        "port": port_num,
                        "service": service,
                        "reason": f"{service} service may have security implications"
                    })
                
                # Check for potentially outdated or concerning product versions
                product = port.get("product", "")
                version = port.get("version", "")
                if product and version:
                    if any(old in version.lower() for old in ["1.0", "2.0", "legacy"]):
                        service_analysis["concerning_services"].append({
                            "port": port_num,
                            "service": service,
                            "reason": f"Potentially outdated {product} version {version}"
                        })
        
        return service_analysis
    
    def _extract_security_findings_summary(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract security findings for AI analysis without hard-coding vulnerabilities."""
        security_findings = {
            "ssl_tls_findings": [],
            "authentication_services": [],
            "network_services": [],
            "potential_attack_vectors": []
        }
        
        ports = result.get("ports", [])
        for port in ports:
            port_num = port.get("port")
            service = port.get("service", "")
            script_output = port.get("script_output", {})
            
            # SSL/TLS findings for AI to analyze
            if any(ssl_script in script_output for ssl_script in ["sslv2", "ssl-cert", "ssl-enum-ciphers"]):
                ssl_finding = {
                    "port": port_num,
                    "service": service,
                    "ssl_scripts_found": [script for script in script_output.keys() if "ssl" in script],
                    "details": {script: script_output[script][:200] + "..." if len(script_output[script]) > 200 else script_output[script] 
                              for script in script_output.keys() if "ssl" in script}
                }
                security_findings["ssl_tls_findings"].append(ssl_finding)
            
            # Authentication services for AI consideration
            auth_services = ["telnet", "ssh", "ftp", "rdp", "vnc", "snmp"]
            if any(auth in service.lower() for auth in auth_services):
                security_findings["authentication_services"].append({
                    "port": port_num,
                    "service": service,
                    "product": port.get("product", ""),
                    "version": port.get("version", "")
                })
            
            # Network services that might be concerning
            network_services = ["upnp", "ssdp", "dhcp", "dns", "ntp", "bootp"]
            if any(net_svc in service.lower() for net_svc in network_services):
                security_findings["network_services"].append({
                    "port": port_num,
                    "service": service,
                    "exposure_note": f"{service} service exposed - may allow network reconnaissance"
                })
            
            # Potential attack vectors for AI to consider
            if service in ["http", "https"] and port.get("device_info", {}).get("device_type"):
                security_findings["potential_attack_vectors"].append({
                    "type": "web_interface",
                    "port": port_num,
                    "service": service,
                    "context": "Network device web interface - potential admin access"
                })
            
            if service == "upnp":
                security_findings["potential_attack_vectors"].append({
                    "type": "upnp_service",
                    "port": port_num,
                    "service": service,
                    "context": "UPnP service - may allow device manipulation"
                })
        
        return security_findings

    def _get_llm_response(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        self._ensure_client()
        
        tools = self.tool_manager.get_tool_definitions()
        
        # Implement context management to prevent length exceeded errors
        messages = self._manage_conversation_context(messages)
        
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
            # Handle context length errors specifically
            if "context_length_exceeded" in str(e) or "maximum context length" in str(e):
                self.on_output("⚠️ Context length exceeded - truncating conversation history", "warning")
                # Truncate more aggressively and retry
                truncated_messages = self._truncate_conversation_aggressively(messages)
                try:
                    response = self.client.chat.completions.create(
                        model=config.OPENAI_MODEL,
                        messages=truncated_messages,
                        tools=tools,
                        tool_choice="auto",
                        max_tokens=min(config.OPENAI_MAX_TOKENS, 2000),  # Reduce max tokens
                        temperature=config.OPENAI_TEMPERATURE,
                    )
                    choice = response.choices[0].message
                    return {
                        "content": choice.content,
                        "tool_calls": choice.tool_calls,
                        "usage": response.usage.model_dump() if response.usage else None
                    }
                except Exception as retry_error:
                    self.on_output(f"❌ LLM API call failed even after truncation: {retry_error}", "error")
                    return {"error": str(retry_error)}
            else:
                self.on_output(f"❌ LLM API call failed: {e}", "error")
                return {"error": str(e)}

    def _manage_conversation_context(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Manage conversation context to prevent length exceeded errors."""
        # Estimate token count (rough approximation: 1 token ≈ 4 characters)
        total_chars = sum(len(json.dumps(msg)) for msg in messages)
        estimated_tokens = total_chars // 4
        
        # Context limit for GPT-3.5/4 (leave room for response)
        max_context_tokens = 5000  # More conservative limit
        
        if estimated_tokens <= max_context_tokens:
            return messages
        
        if self.debug:
            self.on_output(f"🔧 Context management: {estimated_tokens} tokens estimated, truncating...", "info")
        
        return self._smart_truncate_conversation(messages, max_context_tokens)

    def _smart_truncate_conversation(self, messages: List[Dict[str, Any]], max_tokens: int) -> List[Dict[str, Any]]:
        """Smart truncation that preserves tool_calls/tool response structure."""
        if len(messages) <= 2:
            return messages
        
        # Always keep the system message
        managed_messages = [messages[0]]
        
        # Work backwards from the end, keeping complete tool_calls/tool response pairs
        remaining_messages = messages[1:]  # Skip system message
        i = len(remaining_messages) - 1
        temp_messages = []
        
        while i >= 0:
            current_msg = remaining_messages[i]
            
            # If this is a tool response, make sure we include the corresponding tool_calls
            if current_msg.get("role") == "tool":
                # Find the corresponding tool_calls message
                tool_response = current_msg
                temp_messages.insert(0, tool_response)
                
                # Look backwards for the tool_calls message
                j = i - 1
                while j >= 0:
                    if remaining_messages[j].get("tool_calls"):
                        temp_messages.insert(0, remaining_messages[j])
                        i = j - 1  # Continue from before the tool_calls message
                        break
                    j -= 1
                else:
                    # Couldn't find tool_calls, remove the orphaned tool response
                    temp_messages.pop()
                    i -= 1
            else:
                # Regular message or tool_calls message
                if current_msg.get("tool_calls"):
                    # This is a tool_calls message, check if there are corresponding tool responses
                    tool_calls_msg = current_msg
                    tool_responses = []
                    
                    # Look forward for tool responses
                    k = i + 1
                    while k < len(remaining_messages) and remaining_messages[k].get("role") == "tool":
                        tool_responses.append(remaining_messages[k])
                        k += 1
                    
                    # Add the complete set: tool_calls + all its tool responses
                    temp_messages.insert(0, tool_calls_msg)
                    for tool_resp in tool_responses:
                        temp_messages.insert(-1, tool_resp)  # Insert before the last added message
                else:
                    # Regular assistant or user message
                    temp_messages.insert(0, current_msg)
                
                i -= 1
            
            # Check if we're getting close to the token limit
            current_chars = sum(len(json.dumps(managed_messages + temp_messages)))
            if current_chars // 4 > max_tokens and len(temp_messages) > 6:
                break
        
        managed_messages.extend(temp_messages[-10:])  # Keep last 10 messages max
        
        if self.debug:
            self.on_output(f"🔧 Smart truncation: {len(messages)} -> {len(managed_messages)} messages", "info")
        
        return managed_messages

    def _truncate_conversation_aggressively(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Aggressively truncate conversation for emergency context reduction."""
        if len(messages) <= 1:
            return messages
        
        if self.debug:
            self.on_output(f"🔧 Emergency truncation: {len(messages)} messages", "warning")
        
        # Keep only system message and create a summary of the situation
        system_msg = messages[0] if messages else {"role": "system", "content": "You are a cybersecurity agent."}
        
        # Create a summary message instead of trying to preserve tool structure
        summary_content = """Previous analysis summary: Target scan completed. Multiple vulnerabilities identified including UPnP services, web interfaces, and potential command injection points. Focus on providing a final summary of findings and next steps."""
        
        summary_msg = {
            "role": "user", 
            "content": summary_content
        }
        
        truncated = [system_msg, summary_msg]
        
        if self.debug:
            self.on_output(f"🔧 Emergency truncation complete: {len(truncated)} messages", "warning")
        
        return truncated

    def request_final_summary(self):
        summary_prompt = """Provide a final, comprehensive summary of the entire auto-own process based on your intelligent analysis of the target.

MANDATORY REQUIREMENTS for your summary:
1. **Device Intelligence Analysis**: 
   - Identify the specific device model, brand, and type discovered
   - Analyze firmware versions and determine if they appear outdated
   - Explain any security contexts that were identified

2. **Vulnerability Assessment Results**: 
   - Detail vulnerabilities you identified through analysis of:
     * Device-specific research (model-based vulnerabilities)
     * Service security assessment (UPnP, Telnet, HTTP, etc.)
     * SSL/TLS security review (weak protocols, ciphers)
     * Authentication service evaluation
   - Explain your reasoning for why each finding represents a vulnerability

3. **Exploit Database Findings**: 
   - List specific exploits discovered from web searches, Metasploit, or ExploitDB
   - Use ACTUAL exploit names from the data (e.g., "exploit/linux/http/dlink_dir868l_rce")
   - Explain why these exploits are relevant to the identified device/services

4. **Security Analysis**:
   - Analyze concerning services and explain their security implications
   - Evaluate potential attack vectors and their exploitability
   - Assess SSL/TLS configurations and protocol weaknesses

5. **Exploitation Attempts**: 
   - Document any exploits that were attempted and their results
   - Explain your selection criteria for choosing specific exploits

6. **Final Outcome**: 
   - State whether RCE was achieved or not
   - If unsuccessful, explain what prevented exploitation

7. **Technical Recommendations**: 
   - Provide specific remediation steps based on findings
   - Prioritize recommendations by risk level

**ANALYSIS REQUIREMENTS:**
- Base your analysis on the device intelligence, service analysis, and security findings provided
- Demonstrate your reasoning process for identifying vulnerabilities
- Connect device models to specific known vulnerabilities when applicable
- Explain why certain service configurations or versions pose security risks

Your summary should demonstrate intelligent analysis rather than simply listing findings. Show how you connected the scan data to vulnerability research and exploitation decisions."""
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
3. **RESEARCH**: When device models are detected, use `search_device_vulnerabilities` to research device-specific vulnerabilities and exploits.
4. **EXPLOIT**: Based on the analysis and research, select the most promising exploit and use `run_exploit`.

**INTELLIGENT ANALYSIS GUIDANCE:**
When you receive scan and analysis results, you will get comprehensive data including:
- **Device Intelligence**: Extracted device models, brands, firmware versions, and security contexts
- **Service Analysis**: Detailed service information, script results, and concerning services
- **Security Findings**: SSL/TLS configurations, authentication services, and potential attack vectors

**YOUR ANALYSIS RESPONSIBILITIES:**
- **Dynamic Device Research**: When device models are identified, research them dynamically for known vulnerabilities using brand + model patterns
- **Service Vulnerability Assessment**: Analyze services like UPnP, Telnet, HTTP for known security issues based on version and configuration
- **SSL/TLS Security Review**: Examine SSL script results for weak protocols, ciphers, or certificate issues  
- **Version Analysis**: Consider if firmware/software versions appear outdated and vulnerable by cross-referencing with CVE databases
- **Attack Vector Identification**: Evaluate web interfaces, UPnP services, and authentication methods for exploitation potential
- **Port-Specific Analysis**: Research vulnerabilities specific to the services running on each open port

**DYNAMIC SEARCH STRATEGY:**
- **Device Model Research**: Use any detected device models in searches: "[Brand] [Model] vulnerability CVE"
- **Service + Version Research**: "[Service] [Version] vulnerability exploit" 
- **Protocol-Specific Issues**: "[Protocol] command injection", "[Protocol] authentication bypass"
- **Firmware Research**: "[Brand] firmware vulnerability", "router firmware exploit"
- **Port-Specific Vulns**: "port [number] [service] exploit", "[service] remote code execution"
- **CVE Cross-Reference**: Search discovered CVEs in Metasploit and RouterSploit databases

**DECISION MAKING:**
You must intelligently analyze the provided data to determine:
- Which findings represent actual security vulnerabilities
- What the severity and exploitability of issues are  
- Which attack vectors are most promising for achieving RCE
- How to prioritize exploitation attempts

**EXPLOIT PRIORITIZATION:**
1. **Device Research First**: If device models are detected, research them IMMEDIATELY with `search_device_vulnerabilities`
2. **Custom Scripts Priority**: If research suggests custom_scripts (like custom_scripts/dlink_upnp_rce.py), try these FIRST as they're device-specific and highly effective
3. **Research-Verified Exploits**: Prioritize exploits discovered through device research with confirmed CVEs
4. **High Confidence Vulns**: Prioritize vulnerabilities marked with "high" confidence and "critical/high" severity  
5. **Service-Specific**: Focus on high-risk services like UPnP, Telnet, SSH with known issues

**DYNAMIC ANALYSIS AWARENESS:**
The analysis will provide:
- **Device Model Detection**: Automatically extracted device models from scan results
- **Research Requirements**: Vulnerabilities marked with "research_needed": true require you to search for device-specific exploits
- **Research Keywords**: Use provided "research_keywords" arrays to search for device-specific vulnerabilities and exploits
- **Dynamic Recommendations**: Generic vulnerability categories that need device-specific research to find actual exploits
- **Confidence Ratings**: Analysis confidence levels to help prioritization

        **CRITICAL - ACTIVE DEVICE RESEARCH REQUIRED:**
        - When ANY device model is detected, IMMEDIATELY call `search_device_vulnerabilities`
- Do NOT assume specific exploits work without research - always verify through web search
- Use the device research tool to find CVEs, exploits, custom scripts, and Metasploit modules
- Look for actual proof-of-concept exploits and RouterSploit modules for detected devices
- Pay special attention to UPnP services on routers - these are often vulnerable to command injection

Do not deviate from this workflow. Your primary goal is to find the easiest path to compromise. Start by calling `run_nmap_scan` on the target.""" 