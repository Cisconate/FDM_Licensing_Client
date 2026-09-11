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


APPLICATION_STYLESHEET = """
QMainWindow, QDialog { background: #f4f6f8; }
QWidget { color: #172235; }
QTreeWidget { background: #172235; color: #f7f9fb; border: 0; padding: 8px; }
QTreeWidget::item { padding: 7px; }
QTreeWidget::item:selected { background: #2563a6; }
QTreeWidget::item:disabled { color: #b7c2d0; }
QLabel#pageHeading { font-size: 22px; font-weight: 600; color: #172235; }
QLabel#pageSummary { color: #45566c; margin-bottom: 10px; }
QLabel#stepHeading { font-weight: 600; color: #172235; }
QFrame { background: white; color: #172235; border: 1px solid #d8dee8; border-radius: 5px; }
QFrame#activityPanel { padding: 8px; background: #eef5fb; border-color: #9db9d4; }
QFrame#activityPanel[activityState="success"] { background: #edf8f0; border-color: #73a982; }
QFrame#activityPanel[activityState="failure"] { background: #fff1f0; border-color: #c87872; }
QLabel#activityTitle { font-weight: 600; color: #172235; }
QLabel#activityDetail { color: #45566c; }
QProgressBar { min-height: 10px; max-height: 10px; border: 1px solid #aab6c5; border-radius: 4px; background: #e1e7ee; }
QProgressBar::chunk { background: #2563a6; border-radius: 3px; }
QLineEdit, QSpinBox, QListWidget { padding: 6px; background: white; color: #172235; }
QLineEdit[credentialState="missing"] {
    background: #fff0f0; color: #8b0000; border: 1px solid #d32f2f;
    placeholder-text-color: #c85a5a;
}
QLineEdit[credentialState="keychain"] {
    background: #ffffff; color: #172235; placeholder-text-color: #66768a;
}
QLineEdit:disabled, QSpinBox:disabled, QListWidget::item:disabled {
    background: #eef1f5; color: #66768a;
}
QPushButton { padding: 7px 12px; }
QPushButton[workflowAction="true"]:enabled {
    background: #c9f2cf;
    color: #000000;
    border: 1px solid #000000;
    border-radius: 4px;
}
QPushButton[workflowAction="true"]:enabled:hover { background: #b7eabe; }
QPushButton[workflowAction="true"]:enabled:pressed { background: #a5ddae; }
QPushButton[workflowAction="true"]:disabled {
    background: #ffffff;
    color: #c7cdd4;
    border: 1px solid #dfe3e8;
    border-radius: 4px;
}
"""


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
        self._page_widgets: dict[str, QWidget] = {}
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
                    self._page_widgets[capability.page_key] = page
            group.setExpanded(True)

        credentials_page = self._page_widgets.get("credentials")
        workflow_page = self._page_widgets.get("workflow")
        if credentials_page is not None and workflow_page is not None:
            credentials_page.fdm_credentials_changed.connect(
                workflow_page.reload_fdm_credentials
            )
            fdm_page = self._page_widgets.get("fdm")
            if fdm_page is not None:
                credentials_page.fdm_credentials_changed.connect(
                    fdm_page.reload_fdm_credentials
                )

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
    app.setStyleSheet(APPLICATION_STYLESHEET)
    window = MainWindow()
    window.show()
    if smoke_test:
        QTimer.singleShot(100, app.quit)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
