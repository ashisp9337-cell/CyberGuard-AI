"""One shared rate limiter, so routes can add their own limits (e.g. login attempts)."""
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import get_settings

limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"],
                  enabled=get_settings().RATE_LIMIT_ENABLED)
