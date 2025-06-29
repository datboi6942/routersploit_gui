"""Main entry point for RouterSploit GUI."""

import sys
from typing import NoReturn

import structlog

from . import config
from .web_gui import main as web_main


def setup_logging() -> None:
    """Setup structured logging."""
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
    ]
    
    if config.ENVIRONMENT == "development":
        processors.append(structlog.dev.ConsoleRenderer())
    else:
        processors.append(structlog.processors.JSONRenderer())
    
    structlog.configure(
        processors=processors,
        logger_factory=structlog.WriteLoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(config.LOG_LEVEL),
        cache_logger_on_first_use=True,
    )


def main() -> NoReturn:
    """Main entry point for the RouterSploit GUI application."""
    setup_logging()
    logger = structlog.get_logger(__name__)
    
    try:
        logger.info("Starting RouterSploit GUI")
        web_main()
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error("Application crashed", error=str(e))
        sys.exit(1)


if __name__ == "__main__":
    main() 