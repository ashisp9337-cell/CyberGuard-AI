"""One shared rate limiter, so routes can add their own limits (e.g. login attempts)."""
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import get_settings

# default_limits apply to every route WITHOUT its own limit, through SlowAPIASGIMiddleware in main.py (6 Nov audit: before
# that middleware existed the default did nothing). 600 a minute per address: a person clicking fast in the app made
# ~110 a minute in a real-browser test, a flood is stopped.
DEFAULT_LIMIT = "600/minute"
limiter = Limiter(key_func=get_remote_address, default_limits=[DEFAULT_LIMIT],
                  enabled=get_settings().RATE_LIMIT_ENABLED)
