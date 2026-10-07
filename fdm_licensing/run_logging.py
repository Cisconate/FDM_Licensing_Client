"""Secure per-run diagnostic logging shared by CLI and desktop presentations."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import os
from pathlib import Path
import platform
import re
import sys
import threading
import time
from typing import Iterator

from security_validation import safe_error_text


_LOG_NAME = re.compile(
    r"^fdm-licensing-(?:cli|gui)-\d{8}T\d{12}[+-]\d{4}-[0-9a-f]{8}\.log$"
)
_SENSITIVE_FIELD = re.compile(
    r"(?:password|secret|token|authorization|request_code|return_code|release_code|"
    r"request_body|headers?)"
)
_active_log: "RunLog | None" = None
_active_lock = threading.RLock()


def default_log_directory() -> Path:
    """Return the platform-specific per-user diagnostic directory."""
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Logs" / "FDM Licensing"
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA")
        if root:
            return Path(root) / "FDM Licensing" / "Logs"
        return Path.home() / "AppData" / "Local" / "FDM Licensing" / "Logs"
    root = os.environ.get("XDG_STATE_HOME")
    return (
        Path(root) / "fdm-licensing"
        if root
        else Path.home() / ".local" / "state" / "fdm-licensing"
    )


class RunLog:
    """One timestamped, user-private application-run log."""

    def __init__(
        self,
        presentation: str,
        *,
        directory: Path | None = None,
        retention: int = 5,
    ) -> None:
        if presentation not in {"cli", "gui"}:
            raise ValueError("presentation must be cli or gui")
        if isinstance(retention, bool) or not isinstance(retention, int) or retention < 1:
            raise ValueError("retention must be a positive integer")
        self._lock = threading.RLock()
        self._closed = False
        self._started = time.monotonic()
        self.directory = directory or default_log_directory()
        self._prepare_directory()
        now = datetime.now().astimezone()
        unique = os.urandom(4).hex()
        stamp = now.strftime("%Y%m%dT%H%M%S%f%z")
        self.path = self.directory / f"fdm-licensing-{presentation}-{stamp}-{unique}.log"
        if self.path.exists() or self.path.is_symlink():
            raise OSError("run log destination already exists")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(self.path, flags, 0o600)
        self._stream = os.fdopen(descriptor, "w", encoding="utf-8", buffering=1)
        self._retention = retention
        self.event(
            "run.started",
            presentation=presentation,
            python=platform.python_version(),
            platform=sys.platform,
        )
        self._prune()

    def _prepare_directory(self) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink() or not self.directory.is_dir():
            raise OSError("run log directory must be a real directory")
        if os.name != "nt":
            self.directory.chmod(0o700)

    def _prune(self) -> None:
        owned = sorted(
            (
                path for path in self.directory.iterdir()
                if path.is_file() and not path.is_symlink() and _LOG_NAME.fullmatch(path.name)
            ),
            key=lambda path: path.stat().st_mtime_ns,
            reverse=True,
        )
        for path in owned[self._retention:]:
            path.unlink()

    def event(self, name: str, **fields: object) -> None:
        """Write one bounded structured event without accepting secret fields."""
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", name):
            raise ValueError("log event name is invalid")
        rendered = []
        for key, value in sorted(fields.items()):
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,39}", key):
                raise ValueError("log field name is invalid")
            if _SENSITIVE_FIELD.search(key):
                raise ValueError("sensitive fields cannot be written to run logs")
            text = safe_error_text(str(value), limit=300).replace(" ", "_")
            rendered.append(f"{key}={text}")
        timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
        line = f"{timestamp} {name}"
        if rendered:
            line += " " + " ".join(rendered)
        with self._lock:
            if not self._closed:
                self._stream.write(line + "\n")

    @contextmanager
    def phase(self, name: str) -> Iterator[None]:
        started = time.monotonic()
        self.event(f"{name}.started")
        try:
            yield
        except Exception as exc:
            self.event(
                f"{name}.failed",
                elapsed_seconds=f"{time.monotonic() - started:.3f}",
                error_type=type(exc).__name__,
            )
            raise
        else:
            self.event(
                f"{name}.completed",
                elapsed_seconds=f"{time.monotonic() - started:.3f}",
            )

    def close(self, *, outcome: str = "completed") -> None:
        with self._lock:
            if self._closed:
                return
            self.event(
                "run.finished",
                elapsed_seconds=f"{time.monotonic() - self._started:.3f}",
                outcome=outcome,
            )
            self._closed = True
            self._stream.close()
        try:
            self._prune()
        except OSError:
            return


class _NullRunLog:
    path: Path | None = None

    def event(self, _name: str, **_fields: object) -> None:
        return

    @contextmanager
    def phase(self, _name: str) -> Iterator[None]:
        yield

    def close(self, *, outcome: str = "completed") -> None:
        return


NULL_RUN_LOG = _NullRunLog()


def start_run_log(presentation: str) -> RunLog | _NullRunLog:
    """Start the process-wide run log; logging failure never blocks operation."""
    global _active_log
    try:
        created: RunLog | _NullRunLog = RunLog(presentation)
    except (OSError, ValueError):
        created = NULL_RUN_LOG
    with _active_lock:
        _active_log = created if isinstance(created, RunLog) else None
    return created


def active_run_log() -> RunLog | _NullRunLog:
    with _active_lock:
        return _active_log or NULL_RUN_LOG


def log_event(name: str, **fields: object) -> None:
    try:
        active_run_log().event(name, **fields)
    except (OSError, ValueError):
        return


@contextmanager
def log_phase(name: str) -> Iterator[None]:
    if active_run_log() is NULL_RUN_LOG:
        yield
        return
    started = time.monotonic()
    log_event(f"{name}.started")
    try:
        yield
    except Exception as exc:
        log_event(
            f"{name}.failed",
            elapsed_seconds=f"{time.monotonic() - started:.3f}",
            error_type=type(exc).__name__,
        )
        raise
    else:
        log_event(
            f"{name}.completed",
            elapsed_seconds=f"{time.monotonic() - started:.3f}",
        )


def finish_run_log(log: RunLog | _NullRunLog, *, outcome: str) -> None:
    global _active_log
    try:
        log.close(outcome=outcome)
    except (OSError, ValueError):
        pass
    with _active_lock:
        if _active_log is log:
            _active_log = None
