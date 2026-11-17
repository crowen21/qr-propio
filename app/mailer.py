import logging
import smtplib
from email.message import EmailMessage

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import config

_env = Environment(loader=FileSystemLoader(str(config.BASE_DIR / "app" / "templates")),
                   autoescape=select_autoescape(["html"]))


def html_for(subject: str, body: str, boton=None, imagen=None) -> str:
    """Versión HTML con el diseño de la marca, armada desde el mismo texto del correo."""
    parrafos = [" ".join(b.split("\n")) for b in body.strip().split("\n\n")]
    if boton:  # el enlace va en el botón; en el texto queda la frase sin la dirección larga
        limpio = []
        for p in parrafos:
            if boton[1] in p:
                p = p.replace(boton[1], "").strip()
                if p.endswith(":"):
                    p = p[:-1].rstrip() + "."
            if p and not p.startswith(boton[0] + "."):
                limpio.append(p)
        parrafos = limpio
    return _env.get_template("correo.html").render(
        asunto=subject, parrafos=parrafos, boton=boton, imagen=imagen,
        base_url=config.BASE_URL, site=config.SITE_NAME)

log = logging.getLogger("qr.mail")
outbox: list[tuple] = []  # solo en modo sin SMTP (desarrollo y pruebas)


def send(to: str, subject: str, body: str, attachments: list[tuple[str, bytes, str]] = (),
         boton: tuple[str, str] | None = None) -> bool:
    """Envía un correo en texto y HTML. attachments = [(nombre, bytes, subtipo de imagen)];
    la primera imagen adjunta también se muestra dentro del correo. Devuelve True si salió."""
    if not (config.SMTP_HOST or config.SES_REGION):
        outbox.append((to, subject, body, list(attachments)))
        log.warning("SMTP sin configurar. Correo para %s:\n%s\n%s", to, subject, body)
        return False
    msg = EmailMessage()
    msg["From"] = config.SMTP_FROM
    msg["To"] = to
    msg["Subject"] = subject
    if boton and boton[1] not in body:
        body = f"{body}\n\n{boton[0]}: {boton[1]}"
    msg.set_content(body)
    msg.add_alternative(html_for(subject, body, boton, "qr" if attachments else None), subtype="html")
    if attachments:
        name, data, subtype = attachments[0]
        msg.get_payload()[1].add_related(data, maintype="image", subtype=subtype, cid="<qr>", filename=name)
    for name, data, subtype in attachments:
        msg.add_attachment(data, maintype="image", subtype=subtype, filename=name)
    try:
        if config.SES_REGION:
            import boto3  # usa el rol de AWS de la instancia: no hay claves que guardar
            boto3.client("sesv2", region_name=config.SES_REGION).send_email(
                FromEmailAddress=config.SMTP_FROM, Destination={"ToAddresses": [to]},
                Content={"Raw": {"Data": msg.as_bytes()}})
            return True
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as s:
            s.starttls()
            if config.SMTP_USER:
                s.login(config.SMTP_USER, config.SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception:
        log.exception("No se pudo enviar el correo a %s", to)
        return False
