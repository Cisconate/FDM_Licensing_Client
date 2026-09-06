"""Windows-first desktop shell generated from the capability registry."""

from __future__ import annotations

import sys
from collections.abc import Sequence

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QMainWindow,
    QStackedWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
)

from fdm_licensing.capabilities import capabilities_by_category

from .pages import PAGE_FACTORIES


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("FDM Licensing Client")
        self.resize(960, 680)

        container = QWidget()
        layout = QHBoxLayout(container)
        self._navigation = QTreeWidget()
        self._navigation.setHeaderHidden(True)
        self._navigation.setMinimumWidth(245)
        self._pages = QStackedWidget()
        self._page_indexes: dict[str, int] = {}
        layout.addWidget(self._navigation)
        layout.addWidget(self._pages, 1)
        self.setCentralWidget(container)

        for category, capabilities in capabilities_by_category().items():
            group = QTreeWidgetItem([category.value])
            group.setFlags(group.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            self._navigation.addTopLevelItem(group)
            for capability in capabilities:
                item = QTreeWidgetItem([capability.title])
                item.setData(0, Qt.ItemDataRole.UserRole, capability.page_key)
                group.addChild(item)
                if capability.page_key not in self._page_indexes:
                    page = PAGE_FACTORIES[capability.page_key]()
                    self._page_indexes[capability.page_key] = self._pages.addWidget(page)
            group.setExpanded(True)

        self._navigation.currentItemChanged.connect(self._select_page)
        first_group = self._navigation.topLevelItem(0)
        if first_group is not None and first_group.childCount():
            self._navigation.setCurrentItem(first_group.child(0))
        self.statusBar().showMessage("Credentials and tokens are never displayed or logged.")

    def _select_page(
        self, current: QTreeWidgetItem | None, _previous: QTreeWidgetItem | None
    ) -> None:
        if current is None:
            return
        page_key = current.data(0, Qt.ItemDataRole.UserRole)
        if page_key in self._page_indexes:
            self._pages.setCurrentIndex(self._page_indexes[page_key])


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(argv) if argv is not None else list(sys.argv)
    smoke_test = "--smoke-test" in arguments
    if smoke_test:
        arguments.remove("--smoke-test")
    app = QApplication(arguments)
    app.setApplicationName("FDM Licensing Client")
    app.setStyleSheet(
        """
        QMainWindow { background: #f4f6f8; }
        QTreeWidget { background: #172235; color: #f7f9fb; border: 0; padding: 8px; }
        QTreeWidget::item { padding: 7px; }
        QTreeWidget::item:selected { background: #2563a6; }
        QLabel#pageHeading { font-size: 22px; font-weight: 600; color: #172235; }
        QLabel#pageSummary { color: #45566c; margin-bottom: 10px; }
        QLabel#stepHeading { font-weight: 600; color: #172235; }
        QFrame { background: white; border: 1px solid #d8dee8; border-radius: 5px; }
        QLineEdit, QSpinBox { padding: 6px; background: white; }
        QPushButton { padding: 7px 12px; }
        """
    )
    window = MainWindow()
    window.show()
    if smoke_test:
        QTimer.singleShot(100, app.quit)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
