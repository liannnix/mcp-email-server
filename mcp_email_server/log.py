import os
from pathlib import Path

USER_DEFINED_LOG_LEVEL = os.getenv("MCP_EMAIL_SERVER_LOG_LEVEL", "INFO")
LOG_TO_FILE = os.getenv("MCP_EMAIL_SERVER_LOG_FILE", "").strip()
LOG_FILE_ROTATION = os.getenv("MCP_EMAIL_SERVER_LOG_ROTATION", "10 MB")
LOG_FILE_RETENTION = os.getenv("MCP_EMAIL_SERVER_LOG_RETENTION", "7 days")

os.environ["LOGURU_LEVEL"] = USER_DEFINED_LOG_LEVEL

from loguru import logger  # noqa: E402

# Configure file logging if enabled
if LOG_TO_FILE:
    # Ensure log directory exists
    log_path = Path(LOG_TO_FILE)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Add file handler with rotation and retention
    logger.add(
        LOG_TO_FILE,
        level=USER_DEFINED_LOG_LEVEL,
        rotation=LOG_FILE_ROTATION,  # Rotate when file reaches this size
        retention=LOG_FILE_RETENTION,  # Keep logs for this duration
        compression="zip",  # Compress rotated logs
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} - {message}",
        backtrace=True,  # Include traceback on errors
        diagnose=True,   # Include variable values in tracebacks
    )
    logger.info(f"File logging enabled: {LOG_TO_FILE}")

__all__ = ["logger"]
