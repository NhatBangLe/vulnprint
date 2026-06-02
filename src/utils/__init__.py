try:
    from src.utils.logging import configure_logging
except ImportError:
    from .logging import configure_logging
