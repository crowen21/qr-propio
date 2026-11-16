import logging
import smtplib
from email.message import EmailMessage

from . import config

log = logging.getLogger("qr.mail")
outbox: list[tuple] = []  # solo en modo sin SMTP (desarrollo y pruebas)


def send(to: str, subject: str, body: str, attachments: list[tuple[str, bytes, str]] = ()) -> bool:
    """Envía un correo. attachments = [(nombre, bytes, subtipo de imagen)]. Devuelve True si salió."""
    if not config.SMTP_HOST:
        outbox.append((to, subject, body, list(attachments)))
        log.warning("SMTP sin configurar. Correo para %s:\n%s\n%s", to, subject, body)
        return False
    msg = EmailMessage()
    msg["From"] = config.SMTP_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    for name, data, subtype in attachments:
        msg.add_attachment(data, maintype="image", subtype=subtype, filename=name)
    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as s:
            s.starttls()
            if config.SMTP_USER:
                s.login(config.SMTP_USER, config.SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception:
        log.exception("No se pudo enviar el correo a %s", to)
        return False
