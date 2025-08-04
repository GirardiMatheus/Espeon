import logging
import sys
from typing import Optional

# Global configuration
_configured = False
_log_level = logging.INFO
_log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

def configure_logging(
    level: int = logging.INFO,
    format_string: Optional[str] = None,
    log_file: Optional[str] = None
) -> None:
    """
    Configure global logging settings.
    
    :param level: Logging level (e.g., logging.INFO, logging.DEBUG)
    :param format_string: Custom format string for log messages
    :param log_file: Optional file path to write logs to
    """
    global _configured, _log_level, _log_format
    
    if _configured:
        return
    
    _log_level = level
    if format_string:
        _log_format = format_string
    
    # Create formatter
    formatter = logging.Formatter(_log_format)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Suppress noisy third-party loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    
    _configured = True

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name.
    
    :param name: Logger name (typically __name__ of the calling module)
    :return: Configured logger instance
    """
    # Ensure logging is configured
    if not _configured:
        configure_logging()
    
    logger = logging.getLogger(name)
    return logger

def set_log_level(level: int) -> None:
    """
    Change the logging level for all loggers.
    
    :param level: New logging level
    """
    global _log_level
    _log_level = level
    
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    for handler in root_logger.handlers:
        handler.setLevel(level)
