"""Punto de entrada: uvicorn en PANEL_BIND:PANEL_PORT."""
from __future__ import annotations

import logging
import os

import uvicorn

from .main import create_app


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    uvicorn.run(
        create_app(),
        host=os.environ.get("PANEL_BIND", "0.0.0.0"),
        port=int(os.environ.get("PANEL_PORT", "5000")),
        # Detrás de Caddy (PANEL_DOMAIN) se confía en X-Forwarded-For sólo si
        # la conexión viene de localhost, para conocer la IP real del cliente.
        proxy_headers=os.environ.get("TRUST_PROXY", "false").lower() == "true",
        forwarded_allow_ips="127.0.0.1",
        access_log=False,
    )


if __name__ == "__main__":
    main()
