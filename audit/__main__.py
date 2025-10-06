"""
CLI entry point for the audit module.

Usage:
    python -m audit.anchor --help
    python -m audit.anchor --force
    python -m audit.anchor --add-sample
"""

from .anchor import main

if __name__ == "__main__":
    main()
