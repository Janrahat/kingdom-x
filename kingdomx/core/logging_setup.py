"""Centralised logging: rotating file handler, redacting filter, JSON option.

Every record passes through :class:`RedactionFilter`, so a log line physically
cannot contain a credential even if a caller passes one by mistake.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Any

from kingdomx.core.redaction import redact, redact_text

LOGGER_NAME = "kingdomx"
_CONFIGURED = False


class RedactionFilter(logging.Filter):
    """Scrub secrets out of the message, args and any structured extras."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = redact_text(record.msg)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = redact(record.args)
                else:
                    record.args = tuple(redact(arg) for arg in record.args)
            for key, value in list(record.__dict__.items()):
                if key.startswith("_") or key in _STD_FIELDS:
                    continue
                record.__dict__[key] = redact(value)
        except Exception:  # noqa: BLE001 - logging must never raise
            record.msg = "<redaction error>"
            record.args = ()
        return True


_STD_FIELDS = frozenset(
    {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "taskName", "message", "asctime",
    }
)


class JsonFormatter(logging.Formatter):
    """One JSON object per line — safe for piping into log collectors."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in _STD_FIELDS or key.startswith("_"):
                continue
            payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(redact(payload), ensure_ascii=False, default=str)


class TextFormatter(logging.Formatter):
    """Compact, aligned console format for the terminal UI."""

    LEVEL_COLOURS = {
        "DEBUG": "dim",
        "INFO": "cyan",
        "WARNING": "yellow",
        "ERROR": "red",
        "CRITICAL": "bold red",
    }

    def __init__(self, *, colour: bool = False) -> None:
        super().__init__("%(asctime)s %(levelname)-8s %(name)-28s %(message)s", "%H:%M:%S")
        self.colour = colour

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        if not self.colour:
            return text
        tone = self.LEVEL_COLOURS.get(record.levelname)
        if tone is None:
            return text
        return f"[{tone}]{text}[/{tone}]"


def configure(
    level: str = "INFO",
    *,
    log_file: Path | str | None = None,
    json_output: bool = False,
    max_bytes: int = 5 * 1024 * 1024,
    backups: int = 3,
    colour: bool = False,
    quiet: bool = False,
) -> logging.Logger:
    """Attach handlers once per process; safe to call repeatedly."""
    global _CONFIGURED
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    logger.propagate = False

    if _CONFIGURED:
        return logger

    redactor = RedactionFilter()
    handlers: list[logging.Handler] = []

    if not quiet:
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(JsonFormatter() if json_output else TextFormatter(colour=colour))
        stream.addFilter(redactor)
        handlers.append(stream)

    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8"
        )
        file_handler.setFormatter(JsonFormatter() if json_output else TextFormatter())
        file_handler.addFilter(redactor)
        handlers.append(file_handler)

    for handler in handlers:
        logger.addHandler(handler)

    _CONFIGURED = True
    return logger


def get_logger(name: str) -> logging.Logger:
    """Child logger under the ``kingdomx`` namespace."""
    if name.startswith(LOGGER_NAME):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


def reset() -> None:
    """Detach every handler (tests only)."""
    global _CONFIGURED
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # noqa: BLE001
            pass
    _CONFIGURED = False


class LogCapture(list):
    """In-memory handler for tests and the terminal status panel."""

    def __init__(self, level: int = logging.INFO) -> None:
        super().__init__()
        self.handler = logging.Handler(level)
        self.handler.emit = self._emit  # type: ignore[method-assign]
        self.handler.addFilter(RedactionFilter())

    def _emit(self, record: logging.LogRecord) -> None:
        self.append(record)

    def __enter__(self) -> "LogCapture":
        logging.getLogger(LOGGER_NAME).addHandler(self.handler)
        return self

    def __exit__(self, *exc: object) -> None:
        logging.getLogger(LOGGER_NAME).removeHandler(self.handler)

    def messages(self) -> list[str]:
        return [record.getMessage() for record in self]
