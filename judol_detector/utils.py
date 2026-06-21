"""Utilities - Logging setup dan helper functions."""

import logging
import sys
from pathlib import Path


def setup_logging(level: str = "INFO", log_file: str = None):
    """Setup logging configuration.
    
    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional path ke log file
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Format
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_fmt = "%Y-%m-%d %H:%M:%S"
    
    handlers = []
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(fmt, date_fmt))
    handlers.append(console_handler)
    
    # File handler (optional)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(fmt, date_fmt))
        handlers.append(file_handler)
    
    # Root logger
    logging.basicConfig(
        level=log_level,
        handlers=handlers,
        force=True
    )
    
    # Reduce noise from libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def validate_domain(domain: str) -> bool:
    """Validasi apakah string adalah domain yang valid."""
    if not domain or not isinstance(domain, str):
        return False
    domain = domain.strip().lower()
    if len(domain) < 3 or len(domain) > 253:
        return False
    if "." not in domain:
        return False
    # Basic validation
    parts = domain.split(".")
    for part in parts:
        if not part or len(part) > 63:
            return False
    return True


def format_number(n: int) -> str:
    """Format angka dengan separator ribuan."""
    return f"{n:,}"


def truncate(text: str, max_len: int = 60) -> str:
    """Truncate text with ellipsis."""
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."
