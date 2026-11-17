import os
import sys

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-jwt-secret-that-is-longer-than-thirty-two-characters")

ROOT = os.path.abspath(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
