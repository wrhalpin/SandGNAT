"""Entry point for the intake HTTP service.

Run: `sandgnat-intake` (installed by pyproject) which is equivalent to
     `python -m orchestrator.intake_server`.

In production, front this with a proper WSGI server (gunicorn / uwsgi) —
this bootstrap is for dev. For gunicorn:

    gunicorn 'orchestrator.intake_server:wsgi_app()' --bind 0.0.0.0:8080 --workers 2
"""

from __future__ import annotations

import logging
import sys

from .config import get_settings
from .intake_api import create_app


def wsgi_app():  # type: ignore[no-untyped-def]
    """Factory for WSGI servers that need a callable."""
    return create_app()


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    argv = argv or sys.argv[1:]
    settings = get_settings()
    app = create_app()
    app.run(host=settings.intake.bind_host, port=settings.intake.bind_port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
