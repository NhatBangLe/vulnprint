import logging
import sys

# ANSI escape codes for colors
RESET = "\033[0m"
COLORS = {
    logging.DEBUG: "\033[36m",  # Cyan
    logging.INFO: "\033[32m",  # Green
    logging.WARNING: "\033[33m",  # Yellow
    logging.ERROR: "\033[31m",  # Red
    logging.CRITICAL: "\033[1;31m",  # Bold Red
}


class ColoredFormatter(logging.Formatter):
    """Custom logging formatter to display levels in color."""

    def format(self, record: logging.LogRecord) -> str:
        color = COLORS.get(record.levelno, RESET)
        original_levelname = record.levelname
        record.levelname = f"{color}{original_levelname}{RESET}"
        formatted = super().format(record)
        record.levelname = original_levelname
        return formatted


def configure_logging(level_name: str = "INFO") -> None:
    """
    Configures logging handlers and formatter globally.
    """
    # Enable ANSI escape sequences on Windows consoles if applicable
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            h_stdout = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(h_stdout, ctypes.byref(mode)):
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                kernel32.SetConsoleMode(h_stdout, mode.value | 0x0004)
        except Exception:
            pass

    numeric_level = getattr(logging, level_name.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    # Clear existing handlers to avoid duplicate logs
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Redirect logging to stdout for standard CLI feedback
    handler = logging.StreamHandler(sys.stdout)
    formatter = ColoredFormatter("[%(levelname)s] %(name)s - %(message)s")
    handler.setFormatter(formatter)

    root_logger.addHandler(handler)
    root_logger.setLevel(numeric_level)
