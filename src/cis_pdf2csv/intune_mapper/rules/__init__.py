from .base import MappingRule
from .windows_server import WINDOWS_SERVER_2025_RULES

STARTER_RULES = WINDOWS_SERVER_2025_RULES

__all__ = ["STARTER_RULES", "WINDOWS_SERVER_2025_RULES", "MappingRule"]
