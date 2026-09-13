"""Pre-execution checks for SQL you didn't write yourself (mostly LLM output)."""

from .checks import Finding, Result, check_sql

__all__ = ["Finding", "Result", "check_sql"]
__version__ = "0.1.0"
