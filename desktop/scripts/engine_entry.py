"""PyInstaller entry point; keep all application behavior in desktop.engine."""

from desktop.engine.__main__ import main


if __name__ == "__main__":
    raise SystemExit(main())
