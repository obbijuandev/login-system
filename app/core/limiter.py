import os
import uuid
from slowapi import Limiter
from slowapi.util import get_remote_address


def get_remote_address_or_unique(request: object) -> str:
    """Use unique key in test mode to disable rate limiting."""
    if os.getenv("TESTING", "").lower() == "true":
        return str(uuid.uuid4())
    return get_remote_address(request)


limiter = Limiter(key_func=get_remote_address_or_unique)
