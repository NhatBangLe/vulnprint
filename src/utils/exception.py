from typing import Optional
import logging
from pydantic import ValidationError


def handle_validation_error(
    e: ValidationError, logger: Optional[logging.Logger] = None
):
    if logger:
        logger.error(e.title)
    else:
        print(e.title)

    for error in e.errors():
        msg = (
            f"Error Message: {error['msg']}.\n"
            f"Error Location: {error['loc']}.\n"
            f"Error Type: {error['type']}.\n"
            f"Input:\n{error.get('input', '{}')}\n"
        )
        if logger:
            logger.error(msg)
        else:
            print(msg)
