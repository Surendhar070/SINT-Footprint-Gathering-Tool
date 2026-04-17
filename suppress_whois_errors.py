"""
Wrapper to suppress all whois library errors and logging
This module must be imported before any whois usage
"""

import logging
import sys
from io import StringIO

# Configure logging to suppress whois errors
logging.basicConfig(level=logging.CRITICAL, format='')

# Get whois logger and disable it completely
_whois_logger = logging.getLogger('whois')
_whois_logger.setLevel(logging.CRITICAL + 1)
_whois_logger.disabled = True
_whois_logger.propagate = False

# Remove all handlers
for handler in list(_whois_logger.handlers):
    _whois_logger.removeHandler(handler)

# Also configure root logger to not show whois errors
_root_logger = logging.getLogger()
# Add a filter to suppress whois messages
class WhoisFilter(logging.Filter):
    def filter(self, record):
        return 'whois' not in record.name.lower()

_root_logger.addFilter(WhoisFilter())
