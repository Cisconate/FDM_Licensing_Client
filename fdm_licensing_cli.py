"""PyInstaller entry point for the command-line application."""

from fdm_licensing.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
