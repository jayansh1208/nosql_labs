from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from backend.app.config import AI_RATE_LIMIT_PER_MINUTE

_requests: dict[tuple[str, str, str], deque[float]] = defaultdict(deque)
_lock = threading.Lock()


def consume_chat_rate_limit(key: tuple[str, str, str], limit: int | None = None) -> int | None:
    """Return retry-after seconds when over limit; otherwise consume one request."""
    max_requests = AI_RATE_LIMIT_PER_MINUTE if limit is None else max(1, limit)
    now = time.monotonic()
    with _lock:
        bucket = _requests[key]
        while bucket and now - bucket[0] >= 60:
            bucket.popleft()
        if len(bucket) >= max_requests:
            return max(1, int(60 - (now - bucket[0])))
        bucket.append(now)
    return None


def clear_rate_limit_state() -> None:
    """Used by isolated tests only."""
    with _lock:
        _requests.clear()
