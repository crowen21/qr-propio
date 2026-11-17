"""Verificación de seguridad de los enlaces de destino.

Capas:
 1. Forma del enlace: solo http/https, sin credenciales incrustadas, largo acotado.
 2. Destino público: el dominio debe existir y no apuntar a redes internas o privadas.
 3. Lista local de dominios maliciosos (URLhaus, se actualiza a diario).
 4. Google Safe Browsing (opcional, si hay clave configurada).
"""
import ipaddress
import logging
import socket
from urllib.parse import urlsplit

import httpx

from .config import BASE_URL, SAFE_BROWSING_KEY

log = logging.getLogger("qr.urlcheck")
OWN_HOST = urlsplit(BASE_URL).hostname or ""
MAX_LEN = 2000


def resolve(host: str) -> list[str]:
    """Direcciones IP a las que apunta el dominio (lista vacía si no existe)."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return []
    return sorted({i[4][0] for i in infos})


def normalize(url: str) -> str:
    url = url.strip()
    if url and "://" not in url:
        url = "https://" + url
    return url


def _in_blocklist(conn, host: str) -> bool:
    parts = host.split(".")
    candidates = [".".join(parts[i:]) for i in range(len(parts) - 1)]
    marks = ",".join("?" * len(candidates))
    return bool(candidates) and conn.execute(
        f"SELECT 1 FROM blocklist WHERE host IN ({marks}) LIMIT 1", candidates
    ).fetchone() is not None


def _safe_browsing(url: str) -> str | None:
    """Devuelve el tipo de amenaza si Google lo reporta; None si está limpio o no se pudo consultar."""
    if not SAFE_BROWSING_KEY:
        return None
    body = {
        "client": {"clientId": "qr-propio", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = httpx.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": SAFE_BROWSING_KEY}, json=body, timeout=5,
        )
        r.raise_for_status()
        matches = r.json().get("matches") or []
        return matches[0].get("threatType", "AMENAZA") if matches else None
    except Exception as e:  # si Google no responde no bloqueamos al usuario
        log.warning("Safe Browsing no disponible: %s", e)
        return None


def check_url(conn, url: str) -> tuple[bool, str]:
    """(True, "") si el enlace es aceptable; (False, motivo) si no."""
    if not url or len(url) > MAX_LEN:
        return False, "El enlace está vacío o es demasiado largo."
    if any(ch.isspace() or ord(ch) < 32 for ch in url):
        return False, "El enlace contiene espacios o caracteres no válidos."
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").rstrip(".").lower()
        parts.port  # valida el puerto
    except ValueError:
        return False, "El enlace no tiene un formato válido."
    if parts.scheme not in ("http", "https"):
        return False, "Solo se aceptan enlaces http:// o https://."
    if not host:
        return False, "El enlace no tiene un dominio."
    if parts.username or parts.password:
        return False, "No se aceptan enlaces con usuario o clave incrustados (técnica habitual de phishing)."
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return False, "El dominio del enlace no es válido."
    if host == OWN_HOST:
        return False, "El enlace no puede apuntar a este mismo sitio."

    try:
        ips = [str(ipaddress.ip_address(host))]
    except ValueError:
        if "." not in host:
            return False, "El dominio del enlace no es válido."
        ips = resolve(host)
        if not ips:
            return False, "El dominio del enlace no existe o no responde."
    for ip in ips:
        if not ipaddress.ip_address(ip.split("%")[0]).is_global:
            return False, "El enlace apunta a una red interna o privada."

    if _in_blocklist(conn, host):
        return False, "El dominio figura en listas públicas de sitios maliciosos o de phishing."
    threat = _safe_browsing(url)
    if threat:
        return False, f"Google Safe Browsing lo reporta como posible sitio peligroso ({threat})."
    return True, ""
