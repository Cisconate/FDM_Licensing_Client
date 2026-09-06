# Windows application and packaging guide

The project exposes the same application services through a CLI and a PySide6
desktop GUI. Existing top-level modules remain the transport and security
library. The `fdm_licensing` package coordinates user workflows without
duplicating HTTP or credential logic.

## Development launch

Install the GUI dependencies in the project virtual environment:

```powershell
python -m pip install -e ".[gui]"
```

Launch either interface:

```powershell
fdm-licensing capabilities
fdm-licensing-gui
```

The desktop menu is generated from `fdm_licensing/capabilities.py`. To add a
future licensing feature, implement a validated command model, application
service, mocked tests, conditional live test where safe, GUI page, and
capability record. The main window does not need feature-specific changes.

## Unsigned Windows build

Install build dependencies and run the build script:

```powershell
python -m pip install -e ".[gui,build]"
.\build_windows.ps1
```

PyInstaller creates two one-folder applications:

```text
dist\fdm-licensing\fdm-licensing.exe
dist\FDM-Licensing-Client\FDM-Licensing-Client.exe
```

One-folder applications avoid the extraction and startup cost of one-file
bundles and are suitable input for a future MSIX or MSI installer. The current
artifacts are unsigned and intended for development or controlled internal
testing. Public distribution should add Windows code signing and an installer
through a protected release workflow.

The `Windows application build` GitHub workflow can create the same unsigned
artifacts on a Windows runner and performs a CLI executable smoke test before
uploading them.
