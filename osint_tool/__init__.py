"""
OSINT Tool – Enterprise-grade Open Source Intelligence framework.

Usage example::

    from osint_tool import OsintEngine

    engine = OsintEngine()
    results = engine.run(targets=["johndoe"], modules=["username"])
"""

from osint_tool.engine import OsintEngine
from osint_tool.models import FindingLevel, OsintResult

__all__ = ["OsintEngine", "OsintResult", "FindingLevel"]
__version__ = "1.0.0"
