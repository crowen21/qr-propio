import base64
import hashlib
import hmac
import io
import json
import re
import secrets
import time
from collections import defaultdict, deque

import segno
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from PIL import Image
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware

from . import config, db, kinds, mailer, oauth
from .urlcheck import check_url

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware, secret_key=config.SECRET_KEY, session_cookie="qr_sesion",
    max_age=14 * 86400, same_site="lax", https_only=config.BASE_URL.startswith("https://"),
)
app.mount("/static", StaticFiles(directory=config.BASE_DIR / "app" / "static"), name="static")
templates = Jinja2Templates(directory=config.BASE_DIR / "app" / "templates")
db.init()


def qr_data(q) -> dict:
    return json.loads(q["data"]) if q["data"] else {"target": q["target"]}


def _mosaico() -> dict:
    """Módulos del QR del propio sitio, para dibujarlo en la pantalla de acceso."""
    m = [list(r) for r in segno.make(config.BASE_URL, error="m").matrix]
    n = len(m)
    ojos = [(0, 0), (n - 7, 0), (0, n - 7)]
    en_ojo = lambda x, y: any(ox <= x < ox + 7 and oy <= y < oy + 7 for ox, oy in ojos)
    mods = [(x, y, min((x + y) // 3, 17)) for y in range(n) for x in range(n) if m[y][x] and not en_ojo(x, y)]
    return {"n": n, "mods": mods, "ojos": ojos}


templates.env.globals.update(
    mosaico=_mosaico(),
    KINDS=kinds.KINDS, STATIC=kinds.STATIC, proveedores=oauth.enabled,
    resumen=lambda q: kinds.summary(q["kind"], qr_data(q)))

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CODE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # sin caracteres que se confunden
MAX_LOGO_BYTES = 2 * 1024 * 1024
Image.MAX_IMAGE_PIXELS = 20_000_000  # frena imágenes "bomba"
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'none'; "
       "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if config.BASE_URL.startswith("https://"):
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp


# ---------- utilidades ----------

def now() -> int:
    return int(time.time())


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${h.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(calc.hex(), h)
    except Exception:
        return False


DUMMY_HASH = hash_password(secrets.token_hex(8))  # iguala tiempos cuando el correo no existe

_hits: dict[str, deque] = defaultdict(deque)


def rate_limit(request: Request, bucket: str, limit: int = 10, window: int = 600):
    key = f"{bucket}:{request.client.host if request.client else '?'}"
    q, t = _hits[key], time.time()
    while q and q[0] < t - window:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "Demasiados intentos. Espera unos minutos e inténtalo de nuevo.")
    q.append(t)


def csrf_token(request: Request) -> str:
    if "csrf" not in request.session:
        request.session["csrf"] = secrets.token_urlsafe(24)
    return request.session["csrf"]


def check_csrf(request: Request, token: str):
    if not token or not hmac.compare_digest(request.session.get("csrf", ""), token):
        raise HTTPException(403, "La sesión del formulario caducó. Vuelve atrás y recarga la página.")


def current_user(request: Request):
    uid = request.session.get("uid")
    if not uid:
        return None
    with db.connect() as c:
        u = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    # la sesión se invalida si la clave cambió
    if not u or request.session.get("pv") != u["pw_hash"][-12:]:
        request.session.pop("uid", None)
        return None
    return u


def flash(request: Request, text: str, kind: str = "ok"):
    request.session["flash"] = [kind, text]


def render(request: Request, name: str, status: int = 200, **ctx):
    ctx.setdefault("user", current_user(request))
    ctx.update(csrf=csrf_token(request), site=config.SITE_NAME, base_url=config.BASE_URL,
               flash=request.session.pop("flash", None))
    return templates.TemplateResponse(request, name, ctx, status_code=status)


def redirect(path: str):
    return RedirectResponse(path, status_code=303)


def make_token(c, user_id: int, kind: str, hours: int) -> str:
    token = secrets.token_urlsafe(32)
    c.execute("DELETE FROM tokens WHERE user_id=? AND kind=?", (user_id, kind))
    c.execute("INSERT INTO tokens VALUES (?,?,?,?)",
              (hashlib.sha256(token.encode()).hexdigest(), user_id, kind, now() + hours * 3600))
    return token


def find_token(c, token: str, kind: str):
    return c.execute(
        "SELECT * FROM tokens WHERE token_hash=? AND kind=? AND expires_at>?",
        (hashlib.sha256(token.encode()).hexdigest(), kind, now()),
    ).fetchone()


def send_verification(c, user_id: int, email: str, name: str):
    token = make_token(c, user_id, "verify", 24)
    mailer.send(email, f"Confirma tu cuenta en {config.SITE_NAME}",
                f"Hola {name}:\n\nPara activar tu cuenta abre este enlace (vale 24 horas):\n"
                f"{config.BASE_URL}/verificar?token={token}\n\n"
                "Si no creaste esta cuenta, ignora este correo.")


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    if "session" not in request.scope:
        return Response(str(exc.detail), status_code=exc.status_code)
    return render(request, "mensaje.html", status=exc.status_code,
                  titulo="No se pudo completar", texto=exc.detail)


# ---------- páginas públicas ----------

@app.get("/")
def home(request: Request):
    if current_user(request):
        return redirect("/panel")
    return render(request, "inicio.html")


@app.get("/privacidad")
def privacy(request: Request):
    return render(request, "privacidad.html")


@app.get("/salud")
def health():
    return {"ok": True}


@app.get("/registro")
def register_form(request: Request):
    return render(request, "registro.html", form={})


@app.post("/registro")
def register(request: Request, name: str = Form(""), email: str = Form(""),
             password: str = Form(""), csrf: str = Form("")):
    check_csrf(request, csrf)
    rate_limit(request, "registro")
    name, email = " ".join(name.split()), email.strip().lower()
    error = None
    if not 2 <= len(name) <= 80:
        error = "Escribe tu nombre y apellido."
    elif len(email) > 254 or not EMAIL_RE.match(email):
        error = "El correo no tiene un formato válido."
    elif not 10 <= len(password) <= 200:
        error = "La clave debe tener al menos 10 caracteres."
    if error:
        return render(request, "registro.html", status=400, error=error,
                      form={"name": name, "email": email})
    with db.connect() as c:
        u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if u is None:
            cur = c.execute(
                "INSERT INTO users (name,email,pw_hash,created_at) VALUES (?,?,?,?)",
                (name, email, hash_password(password), now()))
            send_verification(c, cur.lastrowid, email, name)
        elif not u["verified"]:
            send_verification(c, u["id"], email, u["name"])
        else:
            mailer.send(email, f"Ya tienes una cuenta en {config.SITE_NAME}",
                        f"Alguien intentó registrarse con este correo. Si fuiste tú, ingresa en "
                        f"{config.BASE_URL}/ingresar o recupera tu clave en {config.BASE_URL}/recuperar")
    # misma respuesta exista o no la cuenta: no revela qué correos están registrados
    return render(request, "mensaje.html", titulo="Revisa tu correo",
                  texto=f"Enviamos un enlace de confirmación a {email}. Ábrelo para activar tu cuenta.")


@app.get("/verificar")
def verify(request: Request, token: str = ""):
    with db.connect() as c:
        t = find_token(c, token, "verify")
        if not t:
            raise HTTPException(400, "El enlace de confirmación no es válido o ya caducó. "
                                     "Regístrate de nuevo para recibir otro.")
        c.execute("UPDATE users SET verified=1 WHERE id=?", (t["user_id"],))
        c.execute("DELETE FROM tokens WHERE token_hash=?", (t["token_hash"],))
    flash(request, "Cuenta confirmada. Ya puedes ingresar.")
    return redirect("/ingresar")


@app.get("/ingresar")
def login_form(request: Request):
    return render(request, "ingresar.html")


@app.post("/ingresar")
def login(request: Request, email: str = Form(""), password: str = Form(""), csrf: str = Form("")):
    check_csrf(request, csrf)
    rate_limit(request, "ingreso")
    email = email.strip().lower()
    with db.connect() as c:
        u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        ok = verify_password(password, u["pw_hash"] if u else DUMMY_HASH) and u is not None
        if ok and not u["verified"]:
            send_verification(c, u["id"], u["email"], u["name"])
            return render(request, "mensaje.html", status=403, titulo="Falta confirmar tu correo",
                          texto="Te reenviamos el enlace de confirmación. Ábrelo y vuelve a ingresar.")
    if not ok:
        return render(request, "ingresar.html", status=401, error="Correo o clave incorrectos.")
    request.session.clear()
    request.session.update(uid=u["id"], pv=u["pw_hash"][-12:])
    return redirect("/panel")


NO_PASSWORD = "!"  # cuentas creadas con Google o Microsoft: ninguna clave coincide


@app.get("/entrar/{provider}")
def oauth_start(request: Request, provider: str):
    if provider not in dict(oauth.enabled()):
        raise HTTPException(404, "Ese método de ingreso no está disponible.")
    rate_limit(request, "ingreso")
    return RedirectResponse(oauth.start(provider, request.session), status_code=302)


@app.get("/entrar/{provider}/retorno")
def oauth_return(request: Request, provider: str, code: str = "", state: str = ""):
    if provider not in dict(oauth.enabled()):
        raise HTTPException(404, "Ese método de ingreso no está disponible.")
    rate_limit(request, "ingreso")
    if not code:  # la persona canceló en la pantalla del proveedor
        request.session.pop("oauth", None)
        return redirect("/ingresar")
    try:
        info = oauth.finish(provider, request.session, code, state)
    except oauth.OAuthError as e:
        raise HTTPException(400, str(e))
    with db.connect() as c:
        user = c.execute("SELECT u.* FROM identities i JOIN users u ON u.id=i.user_id "
                         "WHERE i.provider=? AND i.subject=?", (provider, info["subject"])).fetchone()
        if not user:
            email = info["email"]
            if len(email) > 254 or not EMAIL_RE.match(email):
                raise HTTPException(400, "Tu cuenta no compartió un correo válido, así que no podemos crear el acceso.")
            name = " ".join(info["name"].split())[:80] or email.split("@")[0]
            existing = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if existing and not info["email_trusted"]:
                # No se vincula a una cuenta existente con un correo que el proveedor no garantiza.
                mailer.send(email, f"Intento de ingreso en {config.SITE_NAME}",
                            f"Alguien intentó ingresar con {oauth.PROVIDERS[provider]['label']} usando este correo, "
                            f"que ya tiene una cuenta. Si fuiste tú, ingresa con tu método habitual en "
                            f"{config.BASE_URL}/ingresar")
                return render(request, "mensaje.html", titulo="Revisa tu correo",
                                 texto=f"Te enviamos un correo a {email} para terminar el ingreso.")
            if existing:
                if not existing["verified"]:
                    # alguien pudo registrar este correo sin ser su dueño: su clave deja de servir
                    c.execute("UPDATE users SET pw_hash=?, verified=1 WHERE id=?", (NO_PASSWORD, existing["id"]))
                    c.execute("DELETE FROM tokens WHERE user_id=?", (existing["id"],))
                uid = existing["id"]
            else:
                uid = c.execute("INSERT INTO users (name,email,pw_hash,verified,created_at) VALUES (?,?,?,?,?)",
                                (name, email, NO_PASSWORD, int(info["email_trusted"]), now())).lastrowid
            c.execute("INSERT INTO identities VALUES (?,?,?)", (provider, info["subject"], uid))
            user = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not user["verified"]:
            send_verification(c, user["id"], user["email"], user["name"])
            return render(request, "mensaje.html", titulo="Revisa tu correo",
                             texto=f"Te enviamos un correo a {user['email']} para terminar el ingreso.")
    request.session.clear()
    request.session.update(uid=user["id"], pv=user["pw_hash"][-12:])
    return redirect("/panel")


@app.post("/salir")
def logout(request: Request, csrf: str = Form("")):
    check_csrf(request, csrf)
    request.session.clear()
    return redirect("/")


@app.get("/recuperar")
def forgot_form(request: Request):
    return render(request, "recuperar.html")


@app.post("/recuperar")
def forgot(request: Request, email: str = Form(""), csrf: str = Form("")):
    check_csrf(request, csrf)
    rate_limit(request, "recuperar", limit=5)
    email = email.strip().lower()
    with db.connect() as c:
        u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if u:
            token = make_token(c, u["id"], "reset", 1)
            mailer.send(email, f"Restablece tu clave de {config.SITE_NAME}",
                        f"Hola {u['name']}:\n\nPara crear una clave nueva abre este enlace (vale 1 hora):\n"
                        f"{config.BASE_URL}/restablecer?token={token}\n\n"
                        "Si no lo pediste, ignora este correo.")
    return render(request, "mensaje.html", titulo="Revisa tu correo",
                  texto="Si el correo está registrado, te enviamos un enlace para crear una clave nueva.")


@app.get("/restablecer")
def reset_form(request: Request, token: str = ""):
    with db.connect() as c:
        if not find_token(c, token, "reset"):
            raise HTTPException(400, "El enlace no es válido o ya caducó. Pide uno nuevo.")
    return render(request, "restablecer.html", token=token)


@app.post("/restablecer")
def reset(request: Request, token: str = Form(""), password: str = Form(""), csrf: str = Form("")):
    check_csrf(request, csrf)
    if not 10 <= len(password) <= 200:
        return render(request, "restablecer.html", status=400, token=token,
                      error="La clave debe tener al menos 10 caracteres.")
    with db.connect() as c:
        t = find_token(c, token, "reset")
        if not t:
            raise HTTPException(400, "El enlace no es válido o ya caducó. Pide uno nuevo.")
        # llegar aquí prueba que controla el correo, así que también queda verificado
        c.execute("UPDATE users SET pw_hash=?, verified=1 WHERE id=?",
                  (hash_password(password), t["user_id"]))
        c.execute("DELETE FROM tokens WHERE user_id=?", (t["user_id"],))
    request.session.clear()
    flash(request, "Clave actualizada. Ingresa con tu clave nueva.")
    return redirect("/ingresar")


# ---------- panel ----------

def require_user(request: Request):
    u = current_user(request)
    if not u:
        raise HTTPException(401, "Tienes que ingresar a tu cuenta para ver esta página.")
    return u


def own_qr(c, user, qr_id: int):
    q = c.execute("SELECT * FROM qrs WHERE id=? AND user_id=?", (qr_id, user["id"])).fetchone()
    if not q:
        raise HTTPException(404, "Ese código QR no existe.")
    return q


def panel(request: Request, user, status: int = 200, **ctx):
    with db.connect() as c:
        qrs = c.execute("SELECT * FROM qrs WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    return render(request, "panel.html", status=status, user=user, qrs=qrs, sin_clave=user["pw_hash"] == NO_PASSWORD,
                  max_qrs=config.MAX_QRS_FREE, **ctx)


@app.get("/panel")
def panel_page(request: Request):
    u = current_user(request)
    if not u:
        return redirect("/ingresar")
    return panel(request, u, form={})


def clean_logo(raw: bytes) -> bytes:
    """Valida la imagen subida y la vuelve a codificar como PNG pequeño (descarta metadatos y trucos)."""
    if len(raw) > MAX_LOGO_BYTES:
        raise ValueError("El logo pesa más de 2 MB.")
    try:
        img = Image.open(io.BytesIO(raw))
        if img.format not in ("PNG", "JPEG", "WEBP"):
            raise ValueError
        img = img.convert("RGBA")
    except Exception:
        raise ValueError("El logo debe ser una imagen PNG, JPG o WEBP válida.")
    img.thumbnail((400, 400))
    out = io.BytesIO()
    img.save(out, "PNG", optimize=True)
    return out.getvalue()


def email_qr(user, q) -> bool:
    """Envía la imagen del código al correo de su dueño (nunca a otra dirección)."""
    url = f"{config.BASE_URL}/r/{q['code']}"
    png = qr_bytes(kinds.payload(q["kind"], qr_data(q), url), "png", q["logo"])
    detalle = ("Los datos van dentro del propio código." if q["kind"] in kinds.STATIC
               else f"Dirección corta: {url}\nPuedes cambiar lo que abre desde tu panel sin volver a imprimirlo.")
    return mailer.send(
        user["email"], f"Tu código QR «{q['name']}»",
        f"Hola {user['name']}:\n\nAdjuntamos tu código QR «{q['name']}» "
        f"({kinds.KINDS[q['kind']]['label']}: {kinds.summary(q['kind'], qr_data(q))}).\n\n{detalle}\n\n"
        f"Pruébalo con tu teléfono antes de imprimir.\n\n{config.BASE_URL}/panel",
        [(f"qr-{q['code']}.png", png, "png")])


def qr_form(request: Request, user, kind: str, values: dict, q=None, status: int = 200, error=None):
    return render(request, "formulario.html", status=status, user=user, kind=kind,
                  spec=kinds.KINDS[kind], values=values, q=q, error=error)


def qr_save(request: Request, qr_id: int | None, form: dict):
    """Crea (qr_id=None) o edita un código. El tipo no cambia al editar."""
    check_csrf(request, str(form.get("csrf", "")))
    user = require_user(request)
    rate_limit(request, "qr", limit=60)
    with db.connect() as c:
        q = own_qr(c, user, qr_id) if qr_id else None
        kind = q["kind"] if q else str(form.get("kind", ""))
        if kind not in kinds.KINDS:
            raise HTTPException(400, "Tipo de código no válido.")
        name = " ".join(str(form.get("name", "")).split())[:80]
        logo = q["logo"] if q else None
        try:
            if not name:
                raise ValueError("Ponle un nombre al código para reconocerlo después.")
            if not q and user["plan"] == "free" and c.execute(
                    "SELECT COUNT(*) FROM qrs WHERE user_id=?", (user["id"],)).fetchone()[0] >= config.MAX_QRS_FREE:
                raise ValueError(f"Llegaste al máximo de {config.MAX_QRS_FREE} códigos del plan gratuito.")
            data, target = kinds.build(kind, form)
            if kind == "url":  # los demás tipos van a destinos fijos (wa.me, Instagram, Maps) o a páginas nuestras
                ok, why = check_url(c, target)
                if not ok:
                    raise ValueError(why)
            upload = form.get("logo")
            if form.get("remove_logo"):
                logo = None
            elif upload is not None and getattr(upload, "filename", ""):
                if user["plan"] != "pro":
                    raise ValueError("El logo al centro del QR es una función del plan de pago.")
                logo = clean_logo(upload.file.read(MAX_LOGO_BYTES + 1))
        except ValueError as e:
            values = {k: v for k, v in form.items() if isinstance(v, str)}
            return qr_form(request, user, kind, values, q=q, status=400, error=str(e))
        blob = json.dumps(data, ensure_ascii=False)
        if q:
            c.execute("UPDATE qrs SET name=?, target=?, data=?, logo=?, status='ok', flag_reason=NULL, "
                      "checked_at=? WHERE id=?", (name, target, blob, logo, now(), qr_id))
        else:
            code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(7))
            new_id = c.execute(
                "INSERT INTO qrs (user_id,code,name,kind,target,data,created_at,checked_at) "
                "VALUES (?,?,?,?,?,?,?,?)", (user["id"], code, name, kind, target, blob, now(), now())).lastrowid
            created = c.execute("SELECT * FROM qrs WHERE id=?", (new_id,)).fetchone()
    if q:
        flash(request, "Cambios guardados.")
    elif email_qr(user, created):
        flash(request, f"Código «{name}» creado. Te lo enviamos a {user['email']}.")
    else:
        flash(request, f"Código «{name}» creado.")
    return redirect("/panel")


@app.get("/qr/nuevo")
def qr_new_form(request: Request, tipo: str = "url"):
    user = require_user(request)
    if tipo not in kinds.KINDS:
        raise HTTPException(404, "Ese tipo de código no existe.")
    return qr_form(request, user, tipo, {})


@app.post("/qr/nuevo")
async def qr_new(request: Request):
    return await run_in_threadpool(qr_save, request, None, dict(await request.form()))


@app.get("/qr/{qr_id}/editar")
def qr_edit_form(request: Request, qr_id: int):
    user = require_user(request)
    with db.connect() as c:
        q = own_qr(c, user, qr_id)
    return qr_form(request, user, q["kind"], {**qr_data(q), "name": q["name"]}, q=q)


@app.post("/qr/{qr_id}/editar")
async def qr_edit(request: Request, qr_id: int):
    return await run_in_threadpool(qr_save, request, qr_id, dict(await request.form()))


@app.post("/qr/{qr_id}/estado")
def qr_toggle(request: Request, qr_id: int, csrf: str = Form("")):
    check_csrf(request, csrf)
    user = require_user(request)
    with db.connect() as c:
        own_qr(c, user, qr_id)
        c.execute("UPDATE qrs SET active = 1 - active WHERE id=?", (qr_id,))
    return redirect("/panel")


@app.post("/qr/{qr_id}/correo")
def qr_send(request: Request, qr_id: int, csrf: str = Form("")):
    check_csrf(request, csrf)
    user = require_user(request)
    rate_limit(request, "correo", limit=10)
    with db.connect() as c:
        q = own_qr(c, user, qr_id)
    if email_qr(user, q):
        flash(request, f"Enviamos «{q['name']}» a {user['email']}.")
    else:
        flash(request, "No pudimos enviar el correo en este momento. Descarga el código desde aquí.", "error")
    return redirect("/panel")


@app.post("/qr/{qr_id}/eliminar")
def qr_delete(request: Request, qr_id: int, csrf: str = Form("")):
    check_csrf(request, csrf)
    user = require_user(request)
    with db.connect() as c:
        own_qr(c, user, qr_id)
        c.execute("DELETE FROM qrs WHERE id=?", (qr_id,))
    flash(request, "Código eliminado. Su QR impreso dejó de funcionar.")
    return redirect("/panel")


def qr_bytes(url: str, fmt: str, logo: bytes | None = None, scale: int = 12) -> bytes:
    """Imagen del QR. Con logo se usa la corrección de errores máxima (H) para que siga leyéndose."""
    qr = segno.make(url, error="h" if logo else "m")
    buf = io.BytesIO()
    qr.save(buf, kind=fmt, scale=scale, border=4)
    if not logo:
        return buf.getvalue()
    size = qr.symbol_size(scale=scale, border=4)[0]
    lg = Image.open(io.BytesIO(logo)).convert("RGBA")
    lg.thumbnail((int(size * 0.2), int(size * 0.2)))
    w, h = lg.width + 2 * scale, lg.height + 2 * scale  # margen blanco de un módulo
    x, y = (size - w) // 2, (size - h) // 2
    if fmt == "png":
        img = Image.open(buf).convert("RGBA")
        box = Image.new("RGBA", (w, h), "white")
        box.paste(lg, (scale, scale), lg)
        img.paste(box, (x, y))
        out = io.BytesIO()
        img.save(out, "PNG")
        return out.getvalue()
    small = io.BytesIO()
    lg.save(small, "PNG")
    extra = (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="#fff"/>'
             f'<image x="{x + scale}" y="{y + scale}" width="{lg.width}" height="{lg.height}" '
             f'href="data:image/png;base64,{base64.b64encode(small.getvalue()).decode()}"/>')
    return buf.getvalue().decode().replace("</svg>", extra + "</svg>").encode()


@app.get("/qr/{qr_id}/imagen.{fmt}")
def qr_image(request: Request, qr_id: int, fmt: str, descargar: int = 0):
    user = require_user(request)
    if fmt not in ("svg", "png"):
        raise HTTPException(404, "Formato no disponible.")
    with db.connect() as c:
        q = own_qr(c, user, qr_id)
    data = qr_bytes(kinds.payload(q["kind"], qr_data(q), f"{config.BASE_URL}/r/{q['code']}"), fmt, q["logo"])
    headers = {"Cache-Control": "private, no-store"}
    if descargar:
        headers["Content-Disposition"] = f'attachment; filename="qr-{q["code"]}.{fmt}"'
    return Response(data, media_type="image/svg+xml" if fmt == "svg" else "image/png",
                    headers=headers)


@app.post("/cuenta/eliminar")
def account_delete(request: Request, password: str = Form(""), confirm_email: str = Form(""),
                   csrf: str = Form("")):
    check_csrf(request, csrf)
    user = require_user(request)
    rate_limit(request, "ingreso")
    if user["pw_hash"] == NO_PASSWORD:
        confirmed = confirm_email.strip().lower() == user["email"]
    else:
        confirmed = verify_password(password, user["pw_hash"])
    if not confirmed:
        return panel(request, user, status=400, form={}, error="La confirmación no coincide: la cuenta no se eliminó.")
    with db.connect() as c:
        c.execute("DELETE FROM users WHERE id=?", (user["id"],))  # borra en cascada QR y tokens
    request.session.clear()
    return render(request, "mensaje.html", user=None, titulo="Cuenta eliminada",
                  texto="Borramos tu cuenta, tus datos y todos tus códigos.")


# ---------- redirección del QR ----------

def live_qr(c, code: str):
    q = c.execute("SELECT * FROM qrs WHERE code=?", (code,)).fetchone()
    if not q or not q["active"] or q["kind"] in kinds.STATIC:
        raise HTTPException(404, "Este código QR no existe o fue desactivado por su dueño.")
    if q["expires_at"] and q["expires_at"] < now():
        raise HTTPException(410, "Este código QR ya venció.")
    return q


@app.api_route("/r/{code}", methods=["GET", "HEAD"])
def follow(request: Request, code: str):
    with db.connect() as c:
        q = live_qr(c, code)
        if q["status"] != "ok":
            return render(request, "bloqueado.html", status=403, user=None,
                          google="Google" in (q["flag_reason"] or ""))
        if request.method == "GET":
            c.execute("UPDATE qrs SET scans=scans+1, last_scan_at=? WHERE id=?", (now(), q["id"]))
    if q["kind"] in kinds.REDIRECT:
        return RedirectResponse(q["target"], status_code=302, headers={"Cache-Control": "no-store"})
    d = qr_data(q)
    return render(request, "destino.html", user=None, q=q, d=d, accion=kinds.action(q["kind"], d, code))


@app.get("/r/{code}/contacto.vcf")
def contact_card(code: str):
    with db.connect() as c:
        q = live_qr(c, code)
    if q["kind"] != "vcard":
        raise HTTPException(404, "Este código no es una tarjeta de contacto.")
    return Response(kinds.vcard(qr_data(q)), media_type="text/vcard; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="contacto.vcf"'})
