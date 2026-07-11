import logging
import requests
from urllib.parse import urlparse

logger = logging.getLogger("readonly_guard")

class ReadOnlyViolationError(PermissionError):
    """Exception raised when a write/mutating API request to CrowdStrike is attempted."""
    pass

# Keep reference to the original request method
_original_request = requests.Session.request

def patched_request(self, method: str, url: str, *args, **kwargs):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ""
    
    # Check if the URL points to CrowdStrike API domains
    if "crowdstrike.com" in hostname or "falcon" in hostname:
        normalized_method = method.upper()
        # Strictly allow only GET requests, except for the OAuth2 authentication POST request
        # and specific read-only POST endpoints used for batch lookups.
        if normalized_method != "GET":
            safe_post_paths = [
                "/oauth2/token",
                "/devices/entities/devices/v2",  # Used for batch device detail lookups
                "/devices/entities/devices/v1",
                "/policy/entities/", # used for batch policy details
            ]
            
            if normalized_method == "POST" and any(path in parsed_url.path.lower() for path in safe_post_paths):
                # Allow authentication and safe POST requests to proceed
                return _original_request(self, method, url, *args, **kwargs)
                
            log_msg = f"READ-ONLY VIOLATION BLOCKED: Attempted {normalized_method} to {url}"
            logger.error(log_msg)
            # Raise PermissionError to crash/halt execution of this action
            raise ReadOnlyViolationError(
                f"Unauthorized Write Operation: Falcon AI Copilot is restricted to read-only scopes. "
                f"Blocked execution of {normalized_method} request to CrowdStrike endpoints."
            )
            
    return _original_request(self, method, url, *args, **kwargs)

def enforce_readonly_globally():
    """Monkey-patches the requests library Session object to block non-GET calls to CrowdStrike."""
    requests.Session.request = patched_request
    logger.info("Global Read-Only Guard initialized successfully. Intercepting and securing all CrowdStrike API requests.")
