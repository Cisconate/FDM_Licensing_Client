"""Universal, presentation-only feedback for visible background operations."""

from __future__ import annotations

import math
import time

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QFrame, QLabel, QProgressBar, QVBoxLayout


class ActivityPanel(QFrame):
    """Show responsive activity, elapsed time, and an applicable timeout bound."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("activityPanel")
        self._title = QLabel("")
        self._title.setObjectName("activityTitle")
        self._detail = QLabel("")
        self._detail.setObjectName("activityDetail")
        self._bar = QProgressBar()
        self._bar.setObjectName("activityProgress")
        self._bar.setTextVisible(False)
        self._bar.setAccessibleName("Operation progress")
        layout = QVBoxLayout(self)
        layout.addWidget(self._title)
        layout.addWidget(self._detail)
        layout.addWidget(self._bar)
        self._timer = QTimer(self)
        self._timer.setInterval(250)
        self._timer.timeout.connect(self._refresh)
        self._started_at: float | None = None
        self._timeout_seconds: float | None = None
        self.setVisible(False)

    @property
    def active(self) -> bool:
        return self._timer.isActive()

    def start(self, title: str, *, timeout_seconds: float | None = None) -> None:
        if timeout_seconds is not None and (
            not math.isfinite(timeout_seconds) or timeout_seconds <= 0
        ):
            raise ValueError("activity timeout must be finite and greater than zero")
        self._started_at = time.monotonic()
        self._timeout_seconds = timeout_seconds
        self._title.setText(title)
        self._bar.setRange(0, 0)
        self._bar.setAccessibleDescription(f"{title} is running")
        self.setProperty("activityState", "running")
        self.setVisible(True)
        self._refresh()
        self._timer.start()
        self._refresh_style()

    def succeed(self) -> None:
        self._finish("Completed", "success")

    def fail(self) -> None:
        self._finish("Failed", "failure")

    def _finish(self, outcome: str, state: str) -> None:
        elapsed = self._elapsed()
        self._timer.stop()
        self._bar.setRange(0, 100)
        self._bar.setValue(100 if state == "success" else 0)
        self._detail.setText(f"{outcome} after {elapsed:.1f}s.")
        self._bar.setAccessibleDescription(f"{self._title.text()} {outcome.lower()}")
        self.setProperty("activityState", state)
        self._refresh_style()

    def _elapsed(self, now: float | None = None) -> float:
        if self._started_at is None:
            return 0.0
        current = time.monotonic() if now is None else now
        return max(0.0, current - self._started_at)

    def _refresh(self, now: float | None = None) -> None:
        elapsed = self._elapsed(now)
        if self._timeout_seconds is None:
            timing = f"{elapsed:.1f}s elapsed"
        else:
            remaining = max(0.0, self._timeout_seconds - elapsed)
            if remaining > 0:
                timing = (
                    f"{elapsed:.1f}s elapsed · timeout window has "
                    f"{remaining:.1f}s remaining"
                )
            else:
                timing = (
                    f"{elapsed:.1f}s elapsed · timeout window reached; "
                    "waiting for the operation to return"
                )
        self._detail.setText(f"Working… {timing}.")

    def _refresh_style(self) -> None:
        self.style().unpolish(self)
        self.style().polish(self)
        self.update()
