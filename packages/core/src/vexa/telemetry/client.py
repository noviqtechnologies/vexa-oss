import json
import logging
import platform
import sys
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from vexa import __version__

logger = logging.getLogger(__name__)

class TelemetryClient:
    """Client for sending telemetry data to Vexa backend."""
    
    BASE_URL = "https://vexa-backend-kqcpkmprua-ew.a.run.app"
    FEEDBACK_ENDPOINT = "/api/v1/telemetry/feedback"
    ERROR_REPORT_ENDPOINT = "/api/v1/telemetry/error-report"
    
    def __init__(self):
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": f"Vexa-CLI/{__version__}"
        }

    def _send_request(self, endpoint: str, data: Dict[str, Any]) -> bool:
        """Helper to send JSON POST request."""
        url = f"{self.BASE_URL}{endpoint}"
        
        try:
            json_data = json.dumps(data).encode("utf-8")
            req = urllib.request.Request(url, data=json_data, headers=self.headers, method="POST")
            
            # Initial attempt using system default handlers (including proxies)
            try:
                response = urllib.request.urlopen(req, timeout=5)
            except Exception:
                # Fallback: Retry with direct connection (bypass system proxies)
                # This fixes "getaddrinfo failed" errors caused by misconfigured Windows proxies
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                response = opener.open(req, timeout=10)
            
            with response:
                if response.status in (200, 201):
                    return True
                else:
                    logger.warning(f"Telemetry request failed: {response.status} {response.reason}")
                    return False
                    
        except Exception as e:
            if "getaddrinfo failed" in str(e) or "[Errno 11002]" in str(e):
                logger.warning(f"Network error: DNS resolution failed for {self.BASE_URL}. "
                               "Note: System proxy settings may be interfering.")
            else:
                logger.warning(f"Failed to send telemetry to {endpoint}: {e}")
            return False

    def send_feedback(self, improvement: str, email: Optional[str] = None) -> bool:
        """
        Send user feedback.
        
        Args:
            improvement: The user's feedback or suggestion.
            email: Optional user email for follow-up.
        """
        payload = {
            "use_case": "Development", # Default for generic feedback
            "improvement": improvement,
            "email": email or None,
            "platform": platform.platform(),
            "python_version": platform.python_version()
        }
        return self._send_request(self.FEEDBACK_ENDPOINT, payload)

    def send_error_report(self, error_message: str, traceback_str: str) -> bool:
        """
        Send crash report.
        
        Args:
            error_message: Short description of the error.
            traceback_str: Full stack trace.
        """
        payload = {
            "error_message": error_message,
            "traceback": traceback_str,
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cli_version": __version__
        }
        return self._send_request(self.ERROR_REPORT_ENDPOINT, payload)
