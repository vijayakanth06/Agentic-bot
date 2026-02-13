"""
Vercel Serverless Entry Point.

Exposes the FastAPI `app` so Vercel's @vercel/python runtime can serve it.
"""

import sys
import os

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app  # noqa: E402, F401

# Vercel picks up the `app` object automatically
