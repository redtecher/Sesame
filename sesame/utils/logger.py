import logging
import os
from datetime import datetime
from pathlib import Path

_LOG_DIR = Path(__file__).resolve().parent.parent.parent / "logs"
_CURRENT_RUN_FILE = None


def get_run_log_dir() -> Path:
    return _LOG_DIR


def get_run_log_file() -> Path | None:
    return _CURRENT_RUN_FILE


def setup_run_logging(run_label: str = "") -> Path:
    """Create a timestamped log file for this run. Call once at startup."""
    global _CURRENT_RUN_FILE

    _LOG_DIR.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_label = run_label.replace("/", "_").replace(" ", "_").replace(":", "-")[:40] if run_label else ""
    filename = f"{ts}_{safe_label}.log" if safe_label else f"{ts}.log"

    log_path = _LOG_DIR / filename
    _CURRENT_RUN_FILE = log_path

    # Attach a FileHandler to the root logger so all module loggers write to file
    root_logger = logging.getLogger("sesame")
    if root_logger.level == logging.NOTSET or root_logger.level > logging.DEBUG:
        root_logger.setLevel(logging.DEBUG)

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    ))
    root_logger.addHandler(fh)

    return log_path


def get_logger(name: str) -> logging.Logger:
    prefix = "sesame."
    full_name = f"{prefix}{name}" if not name.startswith(prefix) else name
    logger = logging.getLogger(full_name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    return logger
