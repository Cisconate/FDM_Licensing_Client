"""Background execution that keeps network work off the GUI thread."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, Signal, Slot

from security_validation import safe_error_text


class WorkerSignals(QObject):
    succeeded = Signal(object)
    failed = Signal(str)


class ServiceWorker(QRunnable):
    def __init__(self, operation: Callable[[], Any]) -> None:
        super().__init__()
        self._operation = operation
        self.signals = WorkerSignals()

    @Slot()
    def run(self) -> None:
        try:
            result = self._operation()
        except Exception as exc:
            self.signals.failed.emit(safe_error_text(str(exc), limit=500))
        else:
            self.signals.succeeded.emit(result)


class GuiThreadRelay(QObject):
    """Run worker completion callbacks in this GUI-owned object's thread."""

    def __init__(
        self,
        succeeded: Callable[[Any], None],
        failed: Callable[[str], None],
        finished: Callable[[], None],
        parent: QObject,
    ) -> None:
        super().__init__(parent)
        self._succeeded = succeeded
        self._failed = failed
        self._finished = finished

    @Slot(object)
    def success(self, result: Any) -> None:
        try:
            self._succeeded(result)
        finally:
            self._finished()

    @Slot(str)
    def failure(self, message: str) -> None:
        try:
            self._failed(message)
        finally:
            self._finished()
