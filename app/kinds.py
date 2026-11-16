"""Tipos de código QR.

 - REDIRECT: el QR lleva a nuestro sitio y este redirige (web, WhatsApp, Instagram, mapa).
 - LANDING:  el QR lleva a una página nuestra con el contenido o un botón (correo, llamada, SMS, contacto, texto).
 - STATIC:   los datos van dentro del propio QR (WiFi): no pasa por el servidor, no se cuenta ni se edita sin reimprimir.
"""
import re
from urllib.parse import quote, urlsplit


def F(key, label, type="text", required=True, hint="", max=200, options=None):
    return dict(key=key, label=label, type=type, required=required, hint=hint, max=max, options=options)


TEL_HINT = "Con código de país, por ejemplo +56 9 1234 5678"
KINDS = {
    "url": dict(label="Página web", desc="Sitio, menú, formulario, red social o cualquier enlace",
                fields=[F("target", "Enlace", hint="https://…", max=2000)]),
    "whatsapp": dict(label="WhatsApp", desc="Abre un chat contigo, con un mensaje ya escrito",
                     fields=[F("phone", "Número de WhatsApp", hint=TEL_HINT, max=30),
                             F("message", "Mensaje inicial (opcional)", "textarea", False, "Hola, quiero más información", 500)]),
    "instagram": dict(label="Instagram", desc="Lleva directo a un perfil",
                      fields=[F("username", "Usuario", hint="@tucuenta", max=31)]),
    "ubicacion": dict(label="Ubicación", desc="Abre un lugar en Google Maps",
                      fields=[F("query", "Dirección o coordenadas", hint="Av. Providencia 1234, Santiago", max=300)]),
    "tel": dict(label="Llamada", desc="Botón para llamar a un número",
                fields=[F("phone", "Teléfono", hint=TEL_HINT, max=30)]),
    "sms": dict(label="SMS", desc="Mensaje de texto ya escrito",
                fields=[F("phone", "Teléfono", hint=TEL_HINT, max=30),
                        F("message", "Mensaje (opcional)", "textarea", False, max=300)]),
    "email": dict(label="Correo", desc="Correo con destinatario, asunto y texto listos",
                  fields=[F("to", "Correo de destino", hint="contacto@tunegocio.cl", max=254),
                          F("subject", "Asunto (opcional)", required=False, max=150),
                          F("body", "Mensaje (opcional)", "textarea", False, max=1000)]),
    "vcard": dict(label="Contacto", desc="Tarjeta de presentación que se guarda en el teléfono",
                  fields=[F("full_name", "Nombre completo", max=80),
                          F("phone", "Teléfono (opcional)", required=False, hint=TEL_HINT, max=30),
                          F("email", "Correo (opcional)", required=False, max=254),
                          F("org", "Empresa (opcional)", required=False, max=80),
                          F("title", "Cargo (opcional)", required=False, max=80),
                          F("website", "Sitio web (opcional)", required=False, hint="https://…", max=300)]),
    "texto": dict(label="Texto", desc="Muestra un mensaje, instrucciones o un aviso",
                  fields=[F("text", "Texto", "textarea", max=1500)]),
    "wifi": dict(label="WiFi", desc="Conecta a tu red sin escribir la clave",
                 fields=[F("ssid", "Nombre de la red", max=32),
                         F("security", "Seguridad", "select", options=[("WPA", "WPA / WPA2 / WPA3"), ("WEP", "WEP"), ("nopass", "Sin clave")]),
                         F("password", "Clave de la red", required=False, max=63)]),
}
REDIRECT = {"url", "whatsapp", "instagram", "ubicacion"}
LANDING = {"tel", "sms", "email", "vcard", "texto"}
STATIC = {"wifi"}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def norm_phone(raw: str) -> str:
    s = re.sub(r"[\s\-().]", "", raw)
    if s.startswith("00"):
        s = "+" + s[2:]
    if re.fullmatch(r"9\d{8}", s):          # celular chileno sin código de país
        s = "+56" + s
    elif re.fullmatch(r"\d{10,15}", s):
        s = "+" + s
    if not re.fullmatch(r"\+\d{8,15}", s):
        raise ValueError("Escribe el número con código de país, por ejemplo +56 9 1234 5678.")
    return s


def build(kind: str, form: dict) -> tuple[dict, str]:
    """Valida el formulario y devuelve (datos, destino). Lanza ValueError con un mensaje para el usuario."""
    d = {}
    for f in KINDS[kind]["fields"]:
        v = str(form.get(f["key"], "")).replace("\r\n", "\n").strip()
        if f["type"] != "textarea":
            v = " ".join(v.split())
        if len(v) > f["max"]:
            raise ValueError(f"«{f['label']}» admite hasta {f['max']} caracteres.")
        if f["required"] and not v:
            raise ValueError(f"Falta completar «{f['label']}».")
        d[f["key"]] = v
    target = ""
    if d.get("phone"):
        d["phone"] = norm_phone(d["phone"])
    for key in ("to", "email"):
        if d.get(key) and not EMAIL_RE.match(d[key]):
            raise ValueError("El correo no tiene un formato válido.")
    if kind == "url":
        target = d["target"] if "://" in d["target"] else "https://" + d["target"]
        d["target"] = target
    elif kind == "whatsapp":
        target = f"https://wa.me/{d['phone'][1:]}" + (f"?text={quote(d['message'])}" if d["message"] else "")
    elif kind == "instagram":
        d["username"] = d["username"].lstrip("@")
        if not re.fullmatch(r"[A-Za-z0-9._]{1,30}", d["username"]):
            raise ValueError("El usuario de Instagram solo lleva letras, números, puntos y guiones bajos.")
        target = f"https://www.instagram.com/{d['username']}/"
    elif kind == "ubicacion":
        target = "https://www.google.com/maps/search/?api=1&query=" + quote(d["query"])
    elif kind == "vcard" and d["website"]:
        if "://" not in d["website"]:
            d["website"] = "https://" + d["website"]
        if urlsplit(d["website"]).scheme not in ("http", "https"):
            raise ValueError("El sitio web debe empezar con http:// o https://.")
    elif kind == "wifi":
        if d["security"] not in ("WPA", "WEP", "nopass"):
            raise ValueError("Tipo de seguridad no válido.")
        if d["security"] == "nopass":
            d["password"] = ""
        elif d["security"] == "WPA" and not 8 <= len(d["password"]) <= 63:
            raise ValueError("La clave de una red WPA tiene entre 8 y 63 caracteres.")
        elif not d["password"]:
            raise ValueError("Falta la clave de la red.")
    return d, target


def _wifi_esc(s: str) -> str:
    return re.sub(r'([\;,:"])', r"\\\1", s)


def payload(kind: str, d: dict, short_url: str) -> str:
    """Lo que va escrito dentro del QR."""
    if kind == "wifi":
        pw = f"P:{_wifi_esc(d['password'])};" if d["security"] != "nopass" else ""
        return f"WIFI:T:{d['security']};S:{_wifi_esc(d['ssid'])};{pw};"
    return short_url


def action(kind: str, d: dict, code: str):
    """(texto del botón, enlace) para las páginas de destino."""
    if kind == "tel":
        return "Llamar", f"tel:{d['phone']}"
    if kind == "sms":
        return "Enviar SMS", f"sms:{d['phone']}" + (f"?&body={quote(d['message'])}" if d["message"] else "")
    if kind == "email":
        q = "&".join(f"{k}={quote(d[k])}" for k in ("subject", "body") if d[k])
        return "Escribir correo", f"mailto:{quote(d['to'], safe='@')}" + (f"?{q}" if q else "")
    if kind == "vcard":
        return "Guardar contacto", f"/r/{code}/contacto.vcf"
    return None


def vcard(d: dict) -> str:
    esc = lambda s: re.sub(r"([\;,])", r"\\\1", s).replace("\n", "\\n")
    lines = ["BEGIN:VCARD", "VERSION:3.0", f"N:{esc(d['full_name'])};;;;", f"FN:{esc(d['full_name'])}"]
    for key, prop in (("org", "ORG"), ("title", "TITLE"), ("phone", "TEL;TYPE=CELL"), ("email", "EMAIL"), ("website", "URL")):
        if d.get(key):
            lines.append(f"{prop}:{esc(d[key])}")
    return "\r\n".join(lines + ["END:VCARD", ""])


def summary(kind: str, d: dict) -> str:
    return {
        "url": d.get("target", ""), "whatsapp": d.get("phone", ""), "instagram": "@" + d.get("username", ""),
        "ubicacion": d.get("query", ""), "tel": d.get("phone", ""), "sms": d.get("phone", ""),
        "email": d.get("to", ""), "vcard": d.get("full_name", ""), "wifi": "Red " + d.get("ssid", ""),
        "texto": (d.get("text", "")[:80] + "…") if len(d.get("text", "")) > 80 else d.get("text", ""),
    }[kind]
