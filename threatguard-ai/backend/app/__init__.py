"""ThreatGuard AI backend package."""

import sys

# Keep a single canonical import namespace so the app and tests do not
# resolve module imports against different package roots.
if "backend.app" in sys.modules:
    sys.modules.setdefault("app", sys.modules["backend.app"])
elif "app" in sys.modules:
    sys.modules.setdefault("backend.app", sys.modules["app"])
