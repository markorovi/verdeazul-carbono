"""IP del cliente detrás de los proxies de confianza.

Cloud Run agrega la IP real del cliente AL FINAL de X-Forwarded-For; lo que esté antes lo puede
escribir el propio cliente. Con TRUSTED_PROXY_COUNT = n se toma la n-ésima entrada contando desde
el final, nunca la primera. Si el encabezado tiene menos entradas que proxies, o la entrada no es
una IP, se usa REMOTE_ADDR. Con n = 0 no se confía en el encabezado.

Supuesto a verificar en el despliegue: un solo proxy (el frontal de Cloud Run) delante de la
aplicación y ningún balanceador adicional.
"""

from __future__ import annotations

import ipaddress

from django.conf import settings


def _ip(valor: str) -> str | None:
    try:
        return str(ipaddress.ip_address(valor.strip()))
    except ValueError:
        return None


def ip_cliente(request) -> str:
    remota = _ip(request.META.get("REMOTE_ADDR", "") or "") or "desconocida"
    proxies = int(getattr(settings, "TRUSTED_PROXY_COUNT", 1))
    if proxies <= 0:
        return remota
    partes = [p.strip() for p in (request.META.get("HTTP_X_FORWARDED_FOR", "") or "").split(",") if p.strip()]
    if len(partes) < proxies:
        return remota
    return _ip(partes[-proxies]) or remota
