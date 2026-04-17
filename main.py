import sys
import os
import logging
logging.basicConfig(
    level=logging.CRITICAL,
    format='',
    force=True,
    handlers=[logging.NullHandler()]  # Use NullHandler to suppress all output
)

# Completely disable whois logger
_whois_logger = logging.getLogger('whois')
_whois_logger.setLevel(logging.CRITICAL + 1)
_whois_logger.disabled = True
_whois_logger.propagate = False
_whois_logger.handlers.clear()

# Add filter to root logger to suppress whois messages
class SuppressWhoisFilter(logging.Filter):
    def filter(self, record):
        return 'whois' not in record.name.lower() and 'whois.whois' not in str(record)

_root_logger = logging.getLogger()
_root_logger.addFilter(SuppressWhoisFilter())
_root_logger.setLevel(logging.WARNING)  # Only show warnings and above, not errors from whois

# Add the parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auth_ui import run_auth_then_app

if __name__ == "__main__":
    run_auth_then_app()
