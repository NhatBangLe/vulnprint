try:
    from src.utils.logging import configure_logging
    from src.utils.output_buffer import OutputBuffer
except ImportError:
    from .logging import configure_logging
    from .output_buffer import OutputBuffer
