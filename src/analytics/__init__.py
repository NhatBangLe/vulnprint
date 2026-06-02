try:
    from src.analytics.base import AnalyticsService
    from src.analytics.analytics import CLIAnalyticsService
except ImportError:
    from .base import AnalyticsService
    from .analytics import CLIAnalyticsService
