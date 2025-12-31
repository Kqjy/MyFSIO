from flask import g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect

def get_rate_limit_key():
    """Generate rate limit key based on authenticated user."""
    if hasattr(g, 'principal') and g.principal:
        return g.principal.access_key
    return get_remote_address()

# Shared rate limiter instance; configured in app factory.
limiter = Limiter(key_func=get_rate_limit_key)

# Global CSRF protection for UI routes.
csrf = CSRFProtect()
