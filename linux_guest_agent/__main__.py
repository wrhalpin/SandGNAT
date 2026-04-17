"""`python -m linux_guest_agent` entry point."""

from __future__ import annotations

from .config import from_env
from .watcher import serve


def main() -> None:
    serve(from_env())


if __name__ == "__main__":
    main()
