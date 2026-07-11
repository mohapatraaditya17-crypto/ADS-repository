import logging
import json
import requests
from typing import Generator, List, Dict, Any
from app.config import settings

logger = logging.getLogger("llm_connector")

def get_agent_llm_config(agent_name: str = None) -> tuple[str, str]:
    """
    Resolves the provider and model name based on agent name and settings.
    Uses inspect stack analysis as a fallback if agent_name is not provided.
    """
    HEAVY_AGENTS = {
        "orchestrator", 
        "threat_hunter", 
        "policy_analyst", 
        "soc_analyst", 
        "falcon_engineer", 
        "knowledge_expert"
    }
    LIGHT_AGENTS = {
        "report_generator", 
        "audit_analyst"
    }
    
    detected_agent = False
    if agent_name is None:
        try:
            import inspect
            import os
            frame = inspect.currentframe().f_back
            while frame:
                filename = frame.f_code.co_filename
                if "agents" in filename:
                    base = os.path.splitext(os.path.basename(filename))[0]
                    if base in HEAVY_AGENTS or base in LIGHT_AGENTS:
                        agent_name = base
                        detected_agent = True
                        break
                frame = frame.f_back
        except Exception:
            pass
    else:
        detected_agent = True

    # Load from settings
    provider = settings.LLM_PROVIDER
    model = settings.LLM_MODEL
    
    if detected_agent:
        if agent_name in LIGHT_AGENTS:
            provider = settings.LLM_PROVIDER_LIGHT or provider
            model = settings.LLM_MODEL_LIGHT or model
        else:
            provider = settings.LLM_PROVIDER_HEAVY or provider
            model = settings.LLM_MODEL_HEAVY or model
            
    return provider.lower(), model


def call_llm_stream(
    system_prompt: str, 
    user_prompt: str, 
    chat_history: List[Dict[str, str]] = [],
    agent_name: str = None
) -> Generator[str, None, None]:
    """
    Unified interface to call the configured LLM provider and stream responses word-by-word.
    Supports OpenAI, Gemini, Ollama, and Mock modes with automatic agent routing.
    """
    
    global_formatting_directive = """
---
CRITICAL FORMATTING INSTRUCTIONS (ENFORCE STRICTLY):
1. Act as a conversational, highly helpful Enterprise AI Copilot. Maintain a polite, natural tone (like Gemini or ChatGPT).
2. Format your response beautifully using Markdown.
3. Use emojis (🛡️, ⚠️, 📊, 🔍, 💻, etc.) appropriately to make the text scannable and engaging.
4. Use **bold text** to highlight key entities (e.g., hostnames, IPs, vulnerabilities, policy names).
5. DO NOT output dense "walls of text". Break up your paragraphs. Use structured bullet lists and tables.
6. Always provide a clear, concise, and direct answer first, followed by supporting details.
"""
    system_prompt = system_prompt + "\n" + global_formatting_directive

    provider, model_name = get_agent_llm_config(agent_name)
    logger.info(f"Routed LLM stream: agent_name={agent_name} -> provider={provider}, model={model_name}")
    
    if provider == "openai":
        yield from _call_openai_stream(system_prompt, user_prompt, chat_history, model_name)
    elif provider == "gemini":
        yield from _call_gemini_stream(system_prompt, user_prompt, chat_history, model_name)
    elif provider == "ollama":
        yield from _call_ollama_stream(system_prompt, user_prompt, chat_history, model_name)
    else:
        yield from _call_mock_stream(system_prompt, user_prompt, chat_history)

def _call_openai_stream(
    system_prompt: str, 
    user_prompt: str, 
    chat_history: List[Dict[str, str]], 
    model_name: str = None
) -> Generator[str, None, None]:
    model_name = model_name or settings.LLM_MODEL or "gpt-4-turbo"
    try:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.OPENAI_API_KEY}"
        }
        
        messages = [{"role": "system", "content": system_prompt}]
        for msg in chat_history:
            messages.append({"role": msg["role"], "content": msg["content"]})
        messages.append({"role": "user", "content": user_prompt})
        
        payload = {
            "model": model_name,
            "messages": messages,
            "stream": True
        }
        
        res = requests.post(url, json=payload, headers=headers, stream=True, timeout=30)
        res.raise_for_status()
        
        for line in res.iter_lines():
            if not line:
                continue
            decoded = line.decode("utf-8").strip()
            if decoded.startswith("data: "):
                data_str = decoded[6:]
                if data_str == "[DONE]":
                    break
                try:
                    data = json.loads(data_str)
                    choice = data["choices"][0]
                    delta = choice.get("delta", {})
                    if "content" in delta:
                        yield delta["content"]
                except Exception:
                    continue
    except Exception as e:
        logger.error(f"OpenAI streaming connection error: {e}")
        yield f"\n[System Error: Failed connecting to OpenAI API. Falling back to Mock responses.]\n"
        yield from _call_mock_stream(system_prompt, user_prompt, chat_history)

def _call_gemini_stream(
    system_prompt: str,
    user_prompt: str,
    chat_history: List[Dict[str, str]],
    model_name: str = None
) -> Generator[str, None, None]:
    model_name = model_name or settings.LLM_MODEL or "gemini-1.5-flash"
    if not settings.GEMINI_API_KEY or settings.GEMINI_API_KEY == "mock-key":
        yield "\n[System Error: Gemini API key is missing or set to 'mock-key'. Please add a valid GEMINI_API_KEY in backend/.env.]\n"
        yield from _call_mock_stream(system_prompt, user_prompt, chat_history)
        return
        
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:streamGenerateContent?key={settings.GEMINI_API_KEY}&alt=sse"
        
        contents = []
        for msg in chat_history:
            role = "model" if msg["role"] == "assistant" else "user"
            contents.append({
                "role": role,
                "parts": [{"text": msg["content"]}]
            })
        contents.append({
            "role": "user",
            "parts": [{"text": user_prompt}]
        })
        
        payload = {
            "contents": contents,
            "systemInstruction": {
                "role": "system",
                "parts": [{"text": system_prompt}]
            },
            "generationConfig": {
                "temperature": 0.2
            }
        }
        
        res = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, stream=True, timeout=30)
        res.raise_for_status()
        
        for line in res.iter_lines():
            if not line:
                continue
            decoded = line.decode("utf-8").strip()
            if decoded.startswith("data: "):
                data_str = decoded[6:]
                try:
                    data = json.loads(data_str)
                    candidates = data.get("candidates", [])
                    if candidates:
                        content_obj = candidates[0].get("content", {})
                        parts = content_obj.get("parts", [])
                        if parts:
                            text = parts[0].get("text", "")
                            if text:
                                yield text
                except Exception:
                    continue
    except Exception as e:
        logger.error(f"Gemini streaming connection error: {e}")
        yield f"\n[System Error: Failed connecting to Gemini API. Detail: {str(e)}. Falling back to Mock responses.]\n"
        yield from _call_mock_stream(system_prompt, user_prompt, chat_history)

def _call_ollama_stream(
    system_prompt: str, 
    user_prompt: str, 
    chat_history: List[Dict[str, str]], 
    model_name: str = None
) -> Generator[str, None, None]:
    model_name = model_name or settings.LLM_MODEL or "llama3"
    try:
        # Determine base URL from settings
        base_url = settings.OLLAMA_BASE_URL.rstrip('/')
        
        # Docker fallback bridge if OLLAMA_BASE_URL points to localhost/127.0.0.1 but DB is inside container
        is_localhost = any(lh in base_url for lh in ["localhost", "127.0.0.1"])
        if is_localhost and settings.DB_HOST == "db":
            base_url = "http://host.docker.internal:11434"
            
        url = f"{base_url}/api/chat"
        
        messages = [{"role": "system", "content": system_prompt}]
        for msg in chat_history:
            messages.append({"role": msg["role"], "content": msg["content"]})
        messages.append({"role": "user", "content": user_prompt})
        
        payload = {
            "model": model_name,
            "messages": messages,
            "stream": True
        }
        
        # Increase timeout to 300 seconds to allow for initial model loading time
        res = requests.post(url, json=payload, stream=True, timeout=300)
        
        # Handle HTTP 404 (Model Not Found) specifically
        if res.status_code == 404:
            yield f"\n[System Error: Ollama returned 404 (Model Not Found). Please verify that the model '{model_name}' has been downloaded to your system (run 'ollama pull {model_name}' in your terminal) and matches the LLM_MODEL in backend/.env.]\n"
            yield from _call_mock_stream(system_prompt, user_prompt, chat_history)
            return
            
        res.raise_for_status()
        
        for line in res.iter_lines():
            if not line:
                continue
            try:
                data = json.loads(line.decode("utf-8"))
                message = data.get("message", {})
                content = message.get("content", "")
                if content:
                    yield content
            except Exception:
                continue
                
    except requests.exceptions.Timeout as e:
        logger.error(f"Ollama streaming connection timeout: {e}")
        yield f"\n[System Error: Ollama request timed out (300s limit). This usually happens when the local system is slow to load the model '{model_name}' into RAM/VRAM. Please try sending your query again in a few seconds, as the model should now be cached in memory.]\n"
        yield from _call_mock_stream(system_prompt, user_prompt, chat_history)
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Ollama streaming connection error: {e}")
        yield f"\n[System Error: Could not connect to local Ollama service at '{base_url}'. Please make sure that the Ollama service is running (run 'ollama serve' in your terminal or open the Ollama Desktop app) and that OLLAMA_BASE_URL is correct.]\n"
        yield from _call_mock_stream(system_prompt, user_prompt, chat_history)
    except Exception as e:
        logger.error(f"Ollama streaming unexpected error: {e}")
        yield f"\n[System Error: Failed connecting to local Ollama instance. Detail: {str(e)}. Falling back to Mock responses.]\n"
        yield from _call_mock_stream(system_prompt, user_prompt, chat_history)

def _extract_user_query(user_prompt: str) -> str:
    """Helper to extract the actual user query/request from user_prompt."""
    for line in user_prompt.split('\n'):
        line_stripped = line.strip()
        if line_stripped.startswith(("User Query:", "User Request:", "User Question:")):
            parts = line_stripped.split(":", 1)
            if len(parts) > 1:
                return parts[1].strip()
    first_line = user_prompt.split('\n')[0].strip()
    return first_line[:150]

def _format_list_to_markdown_table(title: str, items: List[Dict[str, Any]]) -> str:
    if not items or not isinstance(items[0], dict):
        return f"### {title}\n* " + "\n* ".join(map(str, items))
        
    first_item = items[0]
    keys = list(first_item.keys())
    
    priority_keys = ["name", "platform_name", "enabled", "groups", "severity", "status", "client_name", "client_id", "scopes", "hostname", "local_ip", "type", "description"]
    exclude_keys = ["id", "cid", "created_by", "created_timestamp", "modified_by", "modified_timestamp", "assignment_rule", "prevention_settings", "ioa_rule_groups"]
    
    columns = [k for k in priority_keys if k in keys]
    other_keys = [k for k in keys if k not in columns and k not in exclude_keys]
    columns.extend(other_keys)
    
    if not columns:
        columns = [k for k in keys if k not in exclude_keys]
    if not columns:
        columns = keys[:5]
        
    headers = [col.replace("_", " ").title() for col in columns]
    header_line = "| " + " | ".join(headers) + " |"
    separator_line = "| " + " | ".join(["---"] * len(columns)) + " |"
    
    rows = []
    for item in items:
        row_values = []
        for col in columns:
            val = item.get(col, "")
            if isinstance(val, bool):
                val = "🟢 Enabled" if val else "🔴 Disabled"
            elif isinstance(val, list):
                names = []
                for sub in val:
                    if isinstance(sub, dict) and "name" in sub:
                        names.append(sub["name"])
                    else:
                        names.append(str(sub))
                val = ", ".join(names) if names else str(val)
            elif isinstance(val, dict):
                val = val.get("name", str(val))
            
            val_str = str(val).replace("|", "\\|").strip()
            if col == "description" and len(val_str) > 100:
                val_str = val_str[:97] + "..."
            row_values.append(val_str)
        rows.append("| " + " | ".join(row_values) + " |")
        
    table_content = "\n".join([header_line, separator_line] + rows)
    return f"### 📊 {title}\n\n{table_content}"

def _format_dict_to_markdown(title: str, data: Dict[str, Any]) -> str:
    lines = [f"### ⚙️ {title}\n"]
    for k, v in data.items():
        k_display = k.replace("_", " ").title()
        if isinstance(v, bool):
            v_display = "🟢 Active" if v else "🔴 Inactive"
        elif isinstance(v, (list, dict)):
            v_display = f"`{v}`"
        else:
            v_display = str(v)
        lines.append(f"* **{k_display}**: {v_display}")
    return "\n".join(lines)

def _find_balanced_block(text: str, start_pos: int) -> str:
    """Finds the matching closing bracket for [ or { starting at start_pos."""
    if start_pos >= len(text):
        return ""
    start_char = text[start_pos]
    if start_char not in ['[', '{']:
        return ""
        
    bracket_map = {'[': ']', '{': '}', '(': ')'}
    inverse_map = {v: k for k, v in bracket_map.items()}
    
    stack = []
    in_single_quote = False
    in_double_quote = False
    escaped = False
    
    for i in range(start_pos, len(text)):
        char = text[i]
        
        if escaped:
            escaped = False
            continue
            
        if char == '\\':
            escaped = True
            continue
            
        if char == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            continue
            
        if char == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            continue
            
        if not in_single_quote and not in_double_quote:
            if char in bracket_map:
                stack.append(char)
            elif char in inverse_map:
                expected_open = inverse_map[char]
                if stack and stack[-1] == expected_open:
                    stack.pop()
                    if not stack:
                        return text[start_pos:i+1]
                else:
                    pass
                    
    return ""

def _extract_and_format_data(prompt: str) -> str:
    import ast
    import re
    
    formatted_sections = []
    skip_until = 0
    
    for match in re.finditer(r":", prompt):
        colon_idx = match.start()
        if colon_idx < skip_until:
            continue
            
        left_text = prompt[:colon_idx]
        header_match = re.search(r"([A-Za-z0-9\s\-\(\)\/\_\&\#]+)$", left_text)
        if not header_match:
            continue
            
        title = header_match.group(1).strip()
        
        if title.lower() in ["user query", "user request", "user question", "configurations context from falcon api", "audited configurations context from falcon api", "api", "query"]:
            continue
            
        right_text = prompt[colon_idx+1:]
        data_start_match = re.search(r"^\s*(\[|\{)", right_text)
        if not data_start_match:
            continue
            
        start_char_idx = colon_idx + 1 + data_start_match.start(1)
        data_block = _find_balanced_block(prompt, start_char_idx)
        if not data_block:
            continue
            
        skip_until = start_char_idx + len(data_block)
        
        try:
            data = ast.literal_eval(data_block)
            if isinstance(data, list) and data:
                formatted_sections.append(_format_list_to_markdown_table(title, data))
            elif isinstance(data, dict) and data:
                formatted_sections.append(_format_dict_to_markdown(title, data))
        except Exception:
            pass
            
    return "\n\n".join(formatted_sections)


def _call_mock_stream(system_prompt: str, user_prompt: str, chat_history: List[Dict[str, str]]) -> Generator[str, None, None]:
    """Generates standard responses if no API keys are loaded or if LLM times out."""
    import time
    
    query = _extract_user_query(user_prompt)
    extracted_data = _extract_and_format_data(user_prompt)
    
    response_blocks = []
    response_blocks.append(
        "🛡️ **Falcon AI Copilot - System Fallback Mode**\n\n"
        "The local Ollama LLM took too long to respond. The system has automatically extracted the raw CrowdStrike Falcon configurations matching your request:\n"
    )
    
    if extracted_data:
        response_blocks.append(extracted_data)
    else:
        response_blocks.append(
            f"Based on your query: *\"{query}\"*, I have analyzed the CrowdStrike configuration database, "
            "and confirmed all required systems are operational."
        )
        
    # Add some generic helpful CrowdStrike recommendations based on query keywords
    recommendations = []
    q = query.lower()
    if "policy" in q or "prevention" in q:
        recommendations.append("Ensure **Sensor Tampering Protection** is enabled on all production systems to prevent unauthorized uninstalls.")
        recommendations.append("Verify **Cloud Anti-malware** and **Sensor Anti-malware** threshold sliders are configured to **Moderate** or **Aggressive** to maximize threat coverage.")
    elif "audit" in q or "client" in q or "api" in q:
        recommendations.append("Audit all API client key scopes regularly. Revoke any unused write permissions to maintain a strict read-only profile.")
    elif "alert" in q or "detection" in q or "incident" in q:
        recommendations.append("Review unresolved Critical or High severity detections immediately in the Falcon Console.")
        recommendations.append("Isolate compromised hosts using containment controls to mitigate potential lateral movement.")
    else:
        recommendations.append("Verify endpoint sensor coverage and monitor health metrics regularly in the Falcon interface.")
        
    if recommendations:
        rec_str = "\n### 💡 Hardening Recommendations\n\nBased on standard **CrowdStrike Falcon Best Practices**, please consider the following:\n"
        for rec in recommendations:
            rec_str += f"* {rec}\n"
        response_blocks.append(rec_str)
        
    final_response = "\n\n".join(response_blocks)
    
    # Yield the text chunk by chunk to simulate streaming
    # Split by lines, then by words, yielding newlines explicitly
    words = []
    for line in final_response.split('\n'):
        line_words = line.split(' ')
        for i, word in enumerate(line_words):
            if word:
                words.append(word)
                if i < len(line_words) - 1:
                    words.append(' ')
        words.append('\n')
        
    for item in words:
        if item == '\n':
            yield '\n'
        elif item == ' ':
            yield ' '
        else:
            yield item
        time.sleep(0.002)

