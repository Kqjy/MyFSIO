"""Application-wide extension instances."""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect

# Shared rate limiter instance; configured in app factory.
limiter = Limiter(key_func=get_remote_address)

# Global CSRF protection for UI routes.
csrf = CSRFProtect()
