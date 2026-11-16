"""Configuración: todo se lee de variables de entorno (ver deploy/qr-propio.env.ejemplo)."""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("QR_DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "qr.db"

# Dirección pública del sitio. Los QR se generan con esta dirección: cámbiala al dominio definitivo ANTES de imprimir.
BASE_URL = os.environ.get("QR_BASE_URL", "http://localhost:8000").rstrip("/")
SITE_NAME = os.environ.get("QR_SITE_NAME", "QR Propio")

# Límite de QR por cuenta en el plan gratuito.
MAX_QRS_FREE = int(os.environ.get("QR_MAX_QRS_FREE", "50"))

# Correo (SMTP). Sin QR_SMTP_HOST los enlaces de verificación se escriben en el registro del servicio.
SMTP_HOST = os.environ.get("QR_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("QR_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("QR_SMTP_USER", "")
SMTP_PASS = os.environ.get("QR_SMTP_PASS", "")
SMTP_FROM = os.environ.get("QR_SMTP_FROM", "")
# Alternativa sin claves: Amazon SES con el rol de la instancia. Si está definida, tiene prioridad sobre SMTP.
SES_REGION = os.environ.get("QR_SES_REGION", "")

# Ingreso con Google / Microsoft. Los botones aparecen solo si están el ID y el secreto.
GOOGLE_CLIENT_ID = os.environ.get("QR_GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("QR_GOOGLE_CLIENT_SECRET", "")
MS_CLIENT_ID = os.environ.get("QR_MS_CLIENT_ID", "")
MS_CLIENT_SECRET = os.environ.get("QR_MS_CLIENT_SECRET", "")

# Seguridad de enlaces.
SAFE_BROWSING_KEY = os.environ.get("QR_SAFE_BROWSING_KEY", "")
BLOCKLIST_URLS = [
    u for u in os.environ.get(
        "QR_BLOCKLIST_URLS", "https://urlhaus.abuse.ch/downloads/hostfile/"
    ).split(",") if u.strip()
]


def _secret_key() -> str:
    key = os.environ.get("QR_SECRET_KEY")
    if key:
        return key
    path = DATA_DIR / "secret.key"
    if not path.exists():
        path.write_text(secrets.token_urlsafe(48))
        path.chmod(0o600)
    return path.read_text().strip()


SECRET_KEY = _secret_key()
