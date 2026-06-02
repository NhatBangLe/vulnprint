try:
    from src.database.base import VulnerabilityRepository
    from src.database.sqlite import SQLiteVulnerabilityRepository
except ImportError:
    from .base import VulnerabilityRepository
    from .sqlite import SQLiteVulnerabilityRepository
