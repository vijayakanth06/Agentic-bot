"""
Vercel Serverless Entry Point.

Exposes the FastAPI `app` so Vercel's @vercel/python runtime can serve it.
"""

import os
import sys

# Ensure the project root is on sys.path so `app.*` imports work
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _root not in sys.path:
    sys.path.insert(0, _root)

# Set VERCEL flag so the app knows it's in serverless mode
os.environ.setdefault("VERCEL", "1")

from app.main import app  # noqa: E402, F401

# Vercel picks up the `app` object automatically
