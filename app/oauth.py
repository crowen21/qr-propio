"""Ingreso con Google y Microsoft (OpenID Connect, flujo de código con PKCE).

El id_token se recibe directo del proveedor por TLS en el intercambio del código, por lo que
(según OpenID Connect Core 3.1.3.7) basta validar emisor, audiencia, vencimiento y nonce.
"""
import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlencode

import httpx

from . import config

GOOGLE = "google"
MICROSOFT = "microsoft"
PROVIDERS = {
    GOOGLE: dict(label="Google",
                 auth="https://accounts.google.com/o/oauth2/v2/auth",
                 token="https://oauth2.googleapis.com/token",
                 client_id=config.GOOGLE_CLIENT_ID, secret=config.GOOGLE_CLIENT_SECRET),
    MICROSOFT: dict(label="Microsoft",
                    auth="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                    token="https://login.microsoftonline.com/common/oauth2/v2.0/token",
                    client_id=config.MS_CLIENT_ID, secret=config.MS_CLIENT_SECRET),
}


class OAuthError(Exception):
    pass


def enabled() -> list[tuple[str, str]]:
    return [(k, p["label"]) for k, p in PROVIDERS.items() if p["client_id"] and p["secret"]]


def redirect_uri(provider: str) -> str:
    return f"{config.BASE_URL}/entrar/{provider}/retorno"


def start(provider: str, session: dict) -> str:
    p = PROVIDERS[provider]
    verifier = secrets.token_urlsafe(48)
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    session["oauth"] = {"p": provider, "s": state, "n": nonce, "v": verifier, "t": int(time.time())}
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return p["auth"] + "?" + urlencode({
        "client_id": p["client_id"], "redirect_uri": redirect_uri(provider), "response_type": "code",
        "scope": "openid email profile", "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "select_account",
    })


def _claims(id_token: str) -> dict:
    try:
        part = id_token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except Exception:
        raise OAuthError("El proveedor devolvió una respuesta que no se pudo leer.")


def finish(provider: str, session: dict, code: str, state: str) -> dict:
    """Devuelve {subject, email, name, email_trusted}. Lanza OAuthError si algo no cuadra."""
    saved = session.pop("oauth", None) or {}
    if (saved.get("p") != provider or not state
            or not secrets.compare_digest(saved.get("s", ""), state)
            or time.time() - saved.get("t", 0) > 600):
        raise OAuthError("El inicio de sesión caducó o no partió en este navegador. Inténtalo de nuevo.")
    p = PROVIDERS[provider]
    try:
        r = httpx.post(p["token"], timeout=10, data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(provider),
            "client_id": p["client_id"], "client_secret": p["secret"], "code_verifier": saved["v"],
        })
        r.raise_for_status()
        token = r.json()["id_token"]
    except Exception:
        raise OAuthError(f"No se pudo completar el ingreso con {p['label']}. Inténtalo de nuevo.")
    c = _claims(token)
    aud = c.get("aud")
    if (aud != p["client_id"] and not (isinstance(aud, list) and p["client_id"] in aud)) \
            or c.get("nonce") != saved["n"] or c.get("exp", 0) < time.time() or not c.get("sub"):
        raise OAuthError("La respuesta del proveedor no pasó la validación de seguridad.")
    if provider == GOOGLE:
        if c.get("iss") not in ("https://accounts.google.com", "accounts.google.com"):
            raise OAuthError("La respuesta del proveedor no pasó la validación de seguridad.")
        return dict(subject=c["sub"], email=(c.get("email") or "").lower(), name=c.get("name") or "",
                    email_trusted=c.get("email_verified") is True)
    tid = c.get("tid", "")
    if not tid or c.get("iss") != f"https://login.microsoftonline.com/{tid}/v2.0":
        raise OAuthError("La respuesta del proveedor no pasó la validación de seguridad.")
    email = c.get("email") or c.get("preferred_username") or ""
    # En Microsoft el correo lo puede fijar el administrador de cualquier organización sin que
    # esté verificado, así que nunca se da por bueno: lo confirmamos nosotros con un enlace.
    return dict(subject=f"{tid}:{c['sub']}", email=email.lower(), name=c.get("name") or "", email_trusted=False)
