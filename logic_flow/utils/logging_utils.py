"""
Logging utilities for the Logic Flow Analysis Tool.

Provides centralized logging configuration with proper file handling
and OS-standard log directory management.
"""

import os
import logging
import logging.handlers
from pathlib import Path
from typing import Optional

from .config import ConfigManager


def setup_logging(
    level: int = logging.INFO,
    log_to_console: bool = True,
    log_to_file: bool = True,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5
) -> logging.Logger:
    """
    Setup centralized logging configuration.

    Args:
        level: Logging level (default: INFO)
        log_to_console: Whether to log to console
        log_to_file: Whether to log to file
        max_bytes: Maximum log file size in bytes
        backup_count: Number of backup log files to keep

    Returns:
        Root logger instance
    """
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(level)

    # Clear existing handlers
    logger.handlers.clear()

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Add console handler
    if log_to_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # Add file handler
    if log_to_file:
        try:
            config_manager = ConfigManager()
            log_dir = config_manager.get_log_dir()
            log_file = log_dir / "logic_flow_analysis.log"

            # Create rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        except Exception as e:
            # Fallback to console if file logging fails
            logger.warning(f"Failed to setup file logging: {e}")

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


class LogContextManager:
    """Context manager for temporary log level changes."""

    def __init__(self, logger: logging.Logger, level: int):
        self.logger = logger
        self.level = level
        self.original_level = logger.level

    def __enter__(self):
        self.logger.setLevel(self.level)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger.setLevel(self.original_level)
