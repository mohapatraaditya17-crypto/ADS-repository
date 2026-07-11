import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.agents.llm import _extract_user_query, _extract_and_format_data, _call_mock_stream

def test_extract_user_query():
    """Verify that user query is cleanly extracted from user_prompt."""
    user_prompt = (
        "User Query: provide me the list of windows prevention policies\n\n"
        "Configurations context from Falcon API:\n"
        "Prevention Policies Configuration:\n"
        "[{'id': '123'}]"
    )
    query = _extract_user_query(user_prompt)
    assert query == "provide me the list of windows prevention policies"

    # Test with User Request label
    user_prompt_request = (
        "User Request: check alerts for the last 24h\n\n"
        "Live CrowdStrike Falcon API Data:\n[]"
    )
    query_request = _extract_user_query(user_prompt_request)
    assert query_request == "check alerts for the last 24h"

def test_extract_and_format_data():
    """Verify that raw policy data is parsed and formatted into markdown table."""
    raw_policies = [
        {
            "id": "ea217beba7884ce08f6e8510f0d4c0a7",
            "name": "ActiveWin",
            "platform_name": "Windows",
            "enabled": True,
            "description": "Managed by Falcon Complete Team"
        },
        {
            "id": "af91e01726074d28acd709a540990a30",
            "name": "MeasuredWin",
            "platform_name": "Windows",
            "enabled": False,
            "description": "Standard baseline policy"
        }
    ]
    
    user_prompt = (
        "User Query: show prevention policies\n\n"
        "Configurations context from Falcon API:\n"
        f"Prevention Policies Configuration:\n{raw_policies}\n"
    )
    
    formatted = _extract_and_format_data(user_prompt)
    
    assert "Prevention Policies Configuration" in formatted
    assert "ActiveWin" in formatted
    assert "MeasuredWin" in formatted
    assert "🟢 Enabled" in formatted
    assert "🔴 Disabled" in formatted
    assert "Platform Name" in formatted

def test_call_mock_stream_fallback():
    """Verify that _call_mock_stream generates the full fallback message with formatting."""
    raw_policies = [
        {
            "id": "ea217beba7884ce08f6e8510f0d4c0a7",
            "name": "ActiveWin",
            "platform_name": "Windows",
            "enabled": True,
            "description": "Managed by Falcon Complete"
        }
    ]
    
    user_prompt = (
        "User Query: list prevention policies\n\n"
        "Configurations context from Falcon API:\n"
        f"Prevention Policies Configuration:\n{raw_policies}\n"
    )
    
    stream = _call_mock_stream("System prompt context", user_prompt, chat_history=[])
    full_response = "".join(list(stream))
    
    assert "System Fallback Mode" in full_response
    assert "ActiveWin" in full_response
    assert "🟢 Enabled" in full_response
    assert "Hardening Recommendations" in full_response
    assert "Sensor Tampering Protection" in full_response

def test_nested_bracket_parsing():
    """Verify that configuration blocks with nested list/dict brackets are parsed correctly."""
    user_prompt = (
        "User Query: list prevention policies\n\n"
        "Configurations context from Falcon API: Prevention Policies Configuration: "
        "[{'id': 'ea217beba7884ce08f6e8510f0d4c0a7', 'name': 'ActiveWin', "
        "'groups': [{'id': 'dc3298a0e2cc436fa959dc499d7df34c', 'name': 'FC - Workstations'}], 'enabled': True}]\n"
    )
    
    formatted = _extract_and_format_data(user_prompt)
    
    assert "Prevention Policies Configuration" in formatted
    assert "ActiveWin" in formatted
    assert "🟢 Enabled" in formatted
    assert "FC - Workstations" in formatted

