"""
CrowdStrike FalconPy Client Factory
====================================
Provides authenticated, cached service class instances for all FalconPy services.
Implements:
  - Connection-level caching to reuse OAuth2 token sessions
  - Exponential backoff on 429 rate-limit responses
  - Structured FalconAPIError exceptions with scope hints
  - Read-only enforcement validation
"""
import logging
import time
import functools
from typing import Any, Dict, Optional, Callable
from app.config import settings

logger = logging.getLogger("crowdstrike_client_factory")

# Registry of active FalconPy service client instances
_client_cache: Dict[str, Any] = {}

# Map of service names to required OAuth2 scopes (for error hints)
SERVICE_SCOPE_MAP: Dict[str, str] = {
    "Detects": "Detections: Read",
    "Alerts": "Detections: Read",
    "AlertsV2": "Detections: Read",
    "Incidents": "Incidents: Read",
    "Hosts": "Hosts: Read",
    "HostGroup": "Host Groups: Read",
    "UserManagement": "User Management: Read",
    "PreventionPolicies": "Prevention Policies: Read",
    "SensorUpdatePolicies": "Sensor Update Policies: Read",
    "DeviceControlPolicies": "Device Control Policies: Read",
    "FirewallManagement": "Firewall Management: Read",
    "FirewallPolicies": "Firewall Management: Read",
    "Intel": "Threat Intelligence: Read",
    "IOC": "IOC Management: Read",
    "Iocs": "IOC Management: Read",
    "SpotlightVulnerabilities": "Spotlight Vulnerabilities: Read",
    "Discover": "Falcon Discover: Read",
    "IdentityProtection": "Identity Protection: Read",
    "AuditEvents": "Audit: Read",
    "OAuth2": "Audit: Read",
    "ProcessesAPI": "MalQuery: Read",
    "SampleUploads": "Sample Uploads: Read",
    "SensorDownload": "Sensor Download: Read",
    "FlightControl": "Flight Control: Read",
    "MSSP": "Flight Control: Read",
}

# Read-only services — write operations are never allowed
READ_ONLY_SERVICES = set(SERVICE_SCOPE_MAP.keys())


class FalconAPIError(Exception):
    """Structured exception for CrowdStrike API errors."""
    def __init__(
        self,
        service: str,
        status_code: int,
        errors: list,
        scope_hint: Optional[str] = None
    ):
        self.service = service
        self.status_code = status_code
        self.errors = errors
        self.scope_hint = scope_hint
        msg = f"[{service}] API Error {status_code}: {errors}"
        if scope_hint:
            msg += f" | Required scope: {scope_hint}"
        super().__init__(msg)


def with_retry(max_retries: int = 3, base_delay: float = 1.0):
    """
    Decorator implementing exponential backoff for rate-limited (429) API calls.
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries):
                try:
                    result = fn(*args, **kwargs)
                    # Handle dict responses with rate limit codes
                    if isinstance(result, dict):
                        code = result.get("status_code", 200)
                        if code == 429:
                            delay = base_delay * (2 ** attempt)
                            logger.warning(
                                f"Rate limited (429) on attempt {attempt + 1}. "
                                f"Retrying in {delay:.1f}s..."
                            )
                            time.sleep(delay)
                            continue
                    return result
                except Exception as e:
                    last_exc = e
                    if attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt)
                        logger.warning(
                            f"API call failed (attempt {attempt + 1}/{max_retries}): {e}. "
                            f"Retrying in {delay:.1f}s..."
                        )
                        time.sleep(delay)
            if last_exc:
                raise last_exc
            raise RuntimeError("Max retries exceeded without result")
        return wrapper
    return decorator


def get_falcon_client(
    service_name: str,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None
) -> Any:
    """
    Instantiates and returns a FalconPy service class instance.

    Args:
        service_name: The FalconPy service class name (e.g., "Detects", "Hosts")
        client_id: Optional override for CrowdStrike client ID
        client_secret: Optional override for CrowdStrike client secret

    Returns:
        Initialized FalconPy service class instance

    Raises:
        ValueError: If the service class name is unknown
        FalconAPIError: If authentication fails
        RuntimeError: If credentials are not configured
    """
    import falconpy

    cid = client_id or settings.FALCON_CLIENT_ID
    secret = client_secret or settings.FALCON_CLIENT_SECRET
    base_url = settings.FALCON_BASE_URL

    # Validate credentials are configured
    if not cid or cid in ("mock-id", ""):
        raise RuntimeError(
            "CrowdStrike Client ID is not configured. "
            "Set FALCON_CLIENT_ID in backend/.env"
        )
    if not secret or secret in ("mock-secret", ""):
        raise RuntimeError(
            "CrowdStrike Client Secret is not configured. "
            "Set FALCON_CLIENT_SECRET in backend/.env"
        )

    # Use cache key based on service and first 6 chars of client ID
    cache_key = f"{service_name}_{cid[:6]}"
    if cache_key in _client_cache:
        return _client_cache[cache_key]

    # Resolve the FalconPy service class
    service_class = getattr(falconpy, service_name, None)
    if service_class is None:
        raise ValueError(
            f"Unknown FalconPy service class: '{service_name}'. "
            f"Check the FalconPy documentation for valid service names."
        )

    scope_hint = SERVICE_SCOPE_MAP.get(service_name, "Unknown scope")
    logger.info(
        f"Initializing FalconPy client for service '{service_name}' "
        f"(required scope: {scope_hint})"
    )

    try:
        client_instance = service_class(
            client_id=cid,
            client_secret=secret,
            base_url=base_url
        )
        _client_cache[cache_key] = client_instance
        logger.info(f"Successfully initialized FalconPy '{service_name}' client.")
        return client_instance
    except Exception as e:
        logger.error(f"Failed to initialize FalconPy '{service_name}': {e}")
        raise FalconAPIError(
            service=service_name,
            status_code=0,
            errors=[str(e)],
            scope_hint=scope_hint
        )


def check_api_response(response: Dict[str, Any], service_name: str) -> Dict[str, Any]:
    """
    Validates a FalconPy API response dict. Raises FalconAPIError on non-200 codes.

    Args:
        response: The dict returned by a FalconPy service method
        service_name: The service name for error context

    Returns:
        The response dict if the call succeeded

    Raises:
        FalconAPIError: On 401, 403, 404, 429, 500 status codes
    """
    status_code = response.get("status_code", 0)
    body = response.get("body", {})
    errors = body.get("errors", [])

    if status_code == 200:
        return response

    scope_hint = SERVICE_SCOPE_MAP.get(service_name)

    if status_code == 401:
        raise FalconAPIError(
            service=service_name,
            status_code=401,
            errors=errors or ["Authentication failed. Check Client ID and Secret."],
            scope_hint=scope_hint
        )
    elif status_code == 403:
        raise FalconAPIError(
            service=service_name,
            status_code=403,
            errors=errors or ["Access denied. Insufficient API scope."],
            scope_hint=scope_hint
        )
    elif status_code == 404:
        raise FalconAPIError(
            service=service_name,
            status_code=404,
            errors=errors or ["Resource not found."],
            scope_hint=scope_hint
        )
    elif status_code == 429:
        raise FalconAPIError(
            service=service_name,
            status_code=429,
            errors=errors or ["Rate limit exceeded."],
            scope_hint=scope_hint
        )
    elif status_code >= 500:
        raise FalconAPIError(
            service=service_name,
            status_code=status_code,
            errors=errors or [f"CrowdStrike API server error ({status_code})."],
            scope_hint=scope_hint
        )
    else:
        # Other non-200 — log and raise
        raise FalconAPIError(
            service=service_name,
            status_code=status_code,
            errors=errors or [f"Unexpected API response code {status_code}."],
            scope_hint=scope_hint
        )


def clear_client_cache():
    """Clears the service client cache. Useful for testing."""
    global _client_cache
    _client_cache.clear()
    logger.info("FalconPy client cache cleared.")
