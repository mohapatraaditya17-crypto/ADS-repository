import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
import requests
from app.middleware.readonly_guard import enforce_readonly_globally, ReadOnlyViolationError

# Activate guard globally for testing
enforce_readonly_globally()

def test_readonly_guard_blocks_post():
    """Verify that outbound POST requests to CrowdStrike domains are blocked."""
    url = "https://api.crowdstrike.com/devices/entities/contain/v1"
    with pytest.raises(ReadOnlyViolationError) as exc_info:
        requests.post(url, json={"ids": ["1234"]})
    
    assert "Unauthorized Write Operation" in str(exc_info.value)
    assert "Blocked execution of POST request" in str(exc_info.value)

def test_readonly_guard_blocks_delete():
    """Verify that outbound DELETE requests to CrowdStrike domains are blocked."""
    url = "https://api.crowdstrike.com/devices/entities/devices/v2"
    with pytest.raises(ReadOnlyViolationError) as exc_info:
        requests.delete(url, params={"ids": "1234"})
        
    assert "Unauthorized Write Operation" in str(exc_info.value)
    assert "Blocked execution of DELETE request" in str(exc_info.value)

def test_readonly_guard_allows_get():
    """
    Verify that GET requests to CrowdStrike domains are not blocked by the guard.
    We mock the underlying session request to avoid making real network calls.
    """
    from unittest.mock import patch
    
    # We patch the original request that requests.Session.request wraps
    # to return a dummy response.
    from app.middleware.readonly_guard import _original_request
    
    with patch("app.middleware.readonly_guard._original_request") as mock_orig:
        mock_orig.return_value = "dummy_response"
        
        # This should execute and call the original request since it is a GET
        response = requests.get("https://api.crowdstrike.com/devices/entities/devices/v2?ids=1234")
        
        assert response == "dummy_response"
        mock_orig.assert_called_once()
