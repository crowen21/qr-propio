import base64
import hashlib
import logging
import hmac
import io
import json
import re
import secrets
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from collections import defaultdict, deque

import segno
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from PIL import Image
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware

from . import config, db, flow, kinds, mailer, oauth
from . import render as qrdraw
from .urlcheck import check_url

log = logging.getLogger("qr.app")
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


GLIFOS = {
    "Q": [".####.", "#....#", "#....#", "#....#", "#..#.#", "#...#.", ".###.#"],
    "R": ["#####.", "#....#", "#....#", "#####.", "#..#..", "#...#.", "#....#"],
}


def _pixeles_qr() -> list[tuple[int, int, bool]]:
    """Cuadritos (x, y, acento) para dibujar las letras «QR» del logo como módulos de un código QR."""
    out = []
    for i, letra in enumerate("QR"):
        for y, fila in enumerate(GLIFOS[letra]):
            for x, ch in enumerate(fila):
                if ch == "#":
                    acento = letra == "Q" and (x, y) in ((3, 4), (4, 5), (5, 6))  # la colita de la Q
                    out.append((x + i * 7, y, acento))
    return out


templates.env.globals.update(
    QR_PIXELES=_pixeles_qr(),
    mosaico=_mosaico(),
    KINDS=kinds.KINDS, STATIC=kinds.STATIC, proveedores=oauth.enabled, PRECIOS=config.PRICES,
    pagos_activos=flow.enabled, pesos=lambda n: f"${n:,.0f}".replace(",", "."),
    resumen=lambda q: kinds.summary(q["kind"], qr_data(q)))

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CODE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # sin caracteres que se confunden
MAX_LOGO_BYTES = 2 * 1024 * 1024
Image.MAX_IMAGE_PIXELS = 20_000_000  # frena imágenes "bomba"
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'none'; "
       "form-action 'self' https://www.flow.cl https://sandbox.flow.cl; frame-ancestors 'none'; base-uri 'none'")


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
                f"Hola {name}:\n\nPara activar tu cuenta, confirma tu correo (el enlace vale 24 horas):\n"
                f"{config.BASE_URL}/verificar?token={token}\n\n"
                "Si no creaste esta cuenta, ignora este correo.",
                boton=("Confirmar mi cuenta", f"{config.BASE_URL}/verificar?token={token}"))


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
                        f"{config.BASE_URL}/ingresar o recupera tu clave en {config.BASE_URL}/recuperar",
                        boton=("Ingresar", f"{config.BASE_URL}/ingresar"))
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
                            f"{config.BASE_URL}/ingresar", boton=("Ingresar", f"{config.BASE_URL}/ingresar"))
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
                        "Si no lo pediste, ignora este correo.",
                        boton=("Crear clave nueva", f"{config.BASE_URL}/restablecer?token={token}"))
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


def is_pro(user) -> bool:
    return user["plan"] == "pro" and (not user["plan_until"] or user["plan_until"] > now())


def free_qr_id(c, user):
    """El código gratuito de la cuenta: el más antiguo que no fue pagado."""
    row = c.execute("SELECT id FROM qrs WHERE user_id=? AND paid=0 ORDER BY id LIMIT 1", (user["id"],)).fetchone()
    return row["id"] if row else None


def premium(user, q) -> bool:
    return is_pro(user) or bool(q["paid"])


def editable(c, user, q) -> bool:
    return premium(user, q) or q["id"] == free_qr_id(c, user)


def mark_text() -> str:
    host = config.BASE_URL.split("://", 1)[-1]
    return f"Crea tu QR gratis en {host}"


def qr_image_bytes(user, q, fmt: str) -> bytes:
    data = kinds.payload(q["kind"], qr_data(q), f"{config.BASE_URL}/r/{q['code']}")
    if premium(user, q):
        return qrdraw.render(fmt, data, logo=q["logo"], fg=q["fg"], bg=q["bg"], frame=q["frame"] or "")
    return qrdraw.render(fmt, data, mark=mark_text())


def fecha(ts) -> str:
    return time.strftime("%d-%m-%Y", time.localtime(ts)) if ts else ""


def panel(request: Request, user, status: int = 200, **ctx):
    with db.connect() as c:
        qrs = c.execute("SELECT * FROM qrs WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
        free_id = free_qr_id(c, user)
    pro = is_pro(user)
    return render(request, "panel.html", status=status, user=user, qrs=qrs, sin_clave=user["pw_hash"] == NO_PASSWORD,
                  pro=pro, pro_hasta=fecha(user["plan_until"]) if pro else "",
                  premium_ids={q["id"] for q in qrs if premium(user, q)},
                  editable_ids={q["id"] for q in qrs if premium(user, q) or q["id"] == free_id},
                  usados=sum(1 for q in qrs if not q["paid"]),
                  max_qrs=config.PRO_QRS if pro else config.FREE_QRS, **ctx)


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
    png = qr_image_bytes(user, q, "png")
    detalle = ("Los datos van dentro del propio código." if q["kind"] in kinds.STATIC
               else f"Dirección corta: {url}\nPuedes cambiar lo que abre desde tu panel sin volver a imprimirlo.")
    return mailer.send(
        user["email"], f"Tu código QR «{q['name']}»",
        f"Hola {user['name']}:\n\nAdjuntamos tu código QR «{q['name']}» "
        f"({kinds.KINDS[q['kind']]['label']}: {kinds.summary(q['kind'], qr_data(q))}).\n\n{detalle}\n\n"
        f"Pruébalo con tu teléfono antes de imprimir.",
        [(f"qr-{q['code']}.png", png, "png")], boton=("Ir a mis códigos", f"{config.BASE_URL}/panel"))


def qr_form(request: Request, user, kind: str, values: dict, q=None, status: int = 200, error=None):
    diseno = premium(user, q) if q else is_pro(user)
    values = {"fg": qrdraw.DEFAULT_FG, "bg": qrdraw.DEFAULT_BG, **{k: v for k, v in values.items() if v}}
    return render(request, "formulario.html", status=status, user=user, kind=kind,
                  spec=kinds.KINDS[kind], values=values, q=q, error=error, diseno=diseno)


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
        if q and not editable(c, user, q):
            raise HTTPException(403, "Este código sigue funcionando, pero para editarlo necesitas el plan Pro "
                                     "o hacerlo permanente desde tu panel.")
        name = " ".join(str(form.get("name", "")).split())[:80]
        logo = q["logo"] if q else None
        diseno = premium(user, q) if q else is_pro(user)
        fg = q["fg"] if q else None
        bg = q["bg"] if q else None
        frame = q["frame"] if q else None
        try:
            if not name:
                raise ValueError("Ponle un nombre al código para reconocerlo después.")
            if not q:
                limit = config.PRO_QRS if is_pro(user) else config.FREE_QRS
                usados = c.execute("SELECT COUNT(*) FROM qrs WHERE user_id=? AND paid=0", (user["id"],)).fetchone()[0]
                if usados >= limit:
                    raise ValueError(
                        f"Tu plan incluye {limit} código{'s' if limit != 1 else ''} y ya lo{'s' if limit != 1 else ''} usaste. "
                        "Puedes hacer permanente uno que ya tengas o pasarte a Pro desde la página de planes.")
            data, target = kinds.build(kind, form)
            if kind == "url":  # los demás tipos van a destinos fijos (wa.me, Instagram, Maps) o a páginas nuestras
                ok, why = check_url(c, target)
                if not ok:
                    raise ValueError(why)
            upload = form.get("logo")
            if upload is not None and getattr(upload, "filename", "") and not diseno:
                raise ValueError("El logo, los colores y el marco son parte de los planes de pago.")
            if diseno:
                fg = str(form.get("fg", "") or qrdraw.DEFAULT_FG).lower()
                bg = str(form.get("bg", "") or qrdraw.DEFAULT_BG).lower()
                problema = qrdraw.check_colors(fg, bg)
                if problema:
                    raise ValueError(problema)
                frame = " ".join(str(form.get("frame", "")).split())[:40] or None
                if form.get("remove_logo"):
                    logo = None
                elif upload is not None and getattr(upload, "filename", ""):
                    logo = clean_logo(upload.file.read(MAX_LOGO_BYTES + 1))
        except ValueError as e:
            values = {k: v for k, v in form.items() if isinstance(v, str)}
            return qr_form(request, user, kind, values, q=q, status=400, error=str(e))
        blob = json.dumps(data, ensure_ascii=False)
        if q:
            c.execute("UPDATE qrs SET name=?, target=?, data=?, logo=?, fg=?, bg=?, frame=?, status='ok', "
                      "flag_reason=NULL, checked_at=? WHERE id=?",
                      (name, target, blob, logo, fg, bg, frame, now(), qr_id))
        else:
            code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(7))
            new_id = c.execute(
                "INSERT INTO qrs (user_id,code,name,kind,target,data,logo,fg,bg,frame,created_at,checked_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (user["id"], code, name, kind, target, blob, logo, fg, bg, frame, now(), now())).lastrowid
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


MEDIA = {"png": "image/png", "svg": "image/svg+xml", "pdf": "application/pdf"}


@app.get("/qr/{qr_id}/imagen.{fmt}")
def qr_image(request: Request, qr_id: int, fmt: str, descargar: int = 0):
    user = require_user(request)
    if fmt not in MEDIA:
        raise HTTPException(404, "Formato no disponible.")
    with db.connect() as c:
        q = own_qr(c, user, qr_id)
    if (fmt == "pdf" or (fmt == "svg" and descargar)) and not premium(user, q):
        raise HTTPException(403, "Los archivos SVG y PDF para imprenta son parte de los planes de pago.")
    headers = {"Cache-Control": "private, no-store"}
    if descargar:
        headers["Content-Disposition"] = f'attachment; filename="qr-{q["code"]}.{fmt}"'
    return Response(qr_image_bytes(user, q, fmt), media_type=MEDIA[fmt], headers=headers)


# ---------- estadísticas ----------

TZ = ZoneInfo("America/Santiago")
DIAS_SEMANA = ["lun", "mar", "mié", "jue", "vie", "sáb", "dom"]


def _barras(valores, etiquetas, cada, titulo):
    """Datos para un gráfico de barras SVG simple (una serie), sin JavaScript."""
    W, H, top, left, bottom = 640, 190, 14, 34, 26
    n = len(valores)
    maximo = max(valores) if any(valores) else 1
    paso = next(p for p in (1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 5000, 10**4, 10**5, 10**6)
                if p * 4 >= maximo)                    # hasta 4 líneas guía con números redondos
    lineas = -(-maximo // paso)
    tope = paso * lineas
    ancho = (W - left) / n
    w = min(ancho - 2, 36)                            # barras delgadas aunque haya pocas
    alto = H - top - bottom
    barras = []
    for i, (v, et) in enumerate(zip(valores, etiquetas)):
        h = alto * v / tope
        barras.append({"x": round(left + i * ancho + (ancho - w) / 2, 2), "w": round(max(1, w), 2),
                       "y": round(top + alto - h, 2), "h": round(h, 2), "v": v, "et": et,
                       "cx": round(left + i * ancho + ancho / 2, 2), "rotulo": i % cada == 0})
    guias = [{"y": round(top + alto - alto * k / lineas, 2), "v": paso * k} for k in range(1, lineas + 1)]
    return {"W": W, "H": H, "base": top + alto, "left": left, "barras": barras, "guias": guias, "titulo": titulo}


@app.get("/qr/{qr_id}/estadisticas")
def qr_stats(request: Request, qr_id: int):
    user = require_user(request)
    with db.connect() as c:
        q = own_qr(c, user, qr_id)
        if not premium(user, q):
            return render(request, "estadisticas.html", user=user, q=q, bloqueado=True)
        desde = now() - 30 * 86400
        filas = c.execute("SELECT ts FROM scans WHERE qr_id=? AND ts>=?", (qr_id, desde)).fetchall()
    hoy = datetime.now(TZ).date()
    dias = [hoy - timedelta(days=29 - i) for i in range(30)]
    por_dia = {d: 0 for d in dias}
    por_hora = [0] * 24
    por_semana = [0] * 7
    for (ts,) in filas:
        dt = datetime.fromtimestamp(ts, TZ)
        if dt.date() in por_dia:
            por_dia[dt.date()] += 1
        por_hora[dt.hour] += 1
        por_semana[dt.weekday()] += 1
    graf_dia = _barras([por_dia[d] for d in dias], [d.strftime("%d-%m") for d in dias], 5, "Escaneos por día")
    graf_hora = _barras(por_hora, [f"{h}:00" for h in range(24)], 3, "Escaneos por hora del día")
    graf_sem = _barras(por_semana, DIAS_SEMANA, 1, "Escaneos por día de la semana")
    siete = sum(por_dia[d] for d in dias[-7:])
    return render(request, "estadisticas.html", user=user, q=q, bloqueado=False,
                  graficos=[graf_dia, graf_hora, graf_sem], total=q["scans"], ultimos30=len(filas),
                  ultimos7=siete, ultimo=datetime.fromtimestamp(q["last_scan_at"], TZ).strftime("%d-%m-%Y %H:%M")
                  if q["last_scan_at"] else "")


# ---------- planes y pagos ----------

PRODUCTS = {"qr": "QR permanente", "pro_mes": "Plan Pro mensual", "pro_anual": "Plan Pro anual"}


@app.get("/planes")
def plans_page(request: Request):
    u = current_user(request)
    return render(request, "planes.html", user=u, pro=bool(u and is_pro(u)),
                  pro_hasta=fecha(u["plan_until"]) if u and is_pro(u) else "")


@app.post("/comprar")
def buy(request: Request, product: str = Form(""), qr_id: int = Form(0), csrf: str = Form("")):
    check_csrf(request, csrf)
    user = require_user(request)
    rate_limit(request, "compra", limit=20)
    if not flow.enabled():
        raise HTTPException(503, "Los pagos todavía no están habilitados. Vuelve a intentarlo pronto.")
    if product not in PRODUCTS:
        raise HTTPException(400, "Producto no válido.")
    subject = f"FacilQR: {PRODUCTS[product]}"
    with db.connect() as c:
        if product == "qr":
            q = own_qr(c, user, qr_id)
            if q["paid"]:
                flash(request, f"«{q['name']}» ya es permanente.")
                return redirect("/panel")
            subject += f" «{q['name'][:40]}»"
        else:
            qr_id = None
            if user["plan"] == "pro" and not user["plan_until"]:
                flash(request, "Tu cuenta ya tiene Pro sin vencimiento.")
                return redirect("/panel")
        order = f"FQ{user['id']}-{secrets.token_hex(5)}"
        pay_id = c.execute(
            "INSERT INTO payments (user_id,qr_id,product,amount,commerce_order,created_at) VALUES (?,?,?,?,?,?)",
            (user["id"], qr_id, product, config.PRICES[product], order, now())).lastrowid
    try:
        url, token = flow.create_payment(order, subject, config.PRICES[product], user["email"])
    except flow.FlowError:
        with db.connect() as c:
            c.execute("UPDATE payments SET status='cancelled' WHERE id=?", (pay_id,))
        flash(request, "No pudimos conectar con el sistema de pago. Inténtalo de nuevo en unos minutos.", "error")
        return redirect("/panel")
    with db.connect() as c:
        c.execute("UPDATE payments SET flow_token=? WHERE id=?", (token, pay_id))
    return RedirectResponse(url, status_code=303)


def apply_purchase(c, pay):
    if pay["product"] == "qr":
        c.execute("UPDATE qrs SET paid=1 WHERE id=? AND user_id=?", (pay["qr_id"], pay["user_id"]))
        return
    u = c.execute("SELECT * FROM users WHERE id=?", (pay["user_id"],)).fetchone()
    if not u or (u["plan"] == "pro" and not u["plan_until"]):
        return  # Pro sin vencimiento: nada que extender
    base = max(now(), u["plan_until"] or 0)
    c.execute("UPDATE users SET plan='pro', plan_until=?, reminded_at=NULL WHERE id=?",
              (base + config.PRO_DAYS[pay["product"]] * 86400, u["id"]))


def process_payment(token: str):
    """Consulta a Flow el estado real del pago y lo aplica una sola vez. Devuelve (pago, estado)."""
    st = flow.payment_status(token)
    status = int(st.get("status") or 0)
    newly_paid = None
    with db.connect() as c:
        pay = c.execute("SELECT * FROM payments WHERE commerce_order=? AND flow_token=?",
                        (str(st.get("commerceOrder", "")), token)).fetchone()
        if not pay:
            return None, status
        amount_ok = round(float(st.get("amount") or 0)) == pay["amount"] and st.get("currency", "CLP") == "CLP"
        if status == flow.PAID and amount_ok:
            if c.execute("UPDATE payments SET status='paid', paid_at=? WHERE id=? AND status!='paid'",
                         (now(), pay["id"])).rowcount:
                apply_purchase(c, pay)
                newly_paid = c.execute("SELECT * FROM users WHERE id=?", (pay["user_id"],)).fetchone()
        elif status in (flow.REJECTED, flow.CANCELLED):
            c.execute("UPDATE payments SET status=? WHERE id=? AND status='pending'",
                      ("rejected" if status == flow.REJECTED else "cancelled", pay["id"]))
        elif status == flow.PAID:
            log.error("Pago %s con monto o moneda distintos a lo esperado: %s", pay["commerce_order"], st)
            status = -1
    if newly_paid:
        mailer.send(newly_paid["email"], f"Pago recibido en {config.SITE_NAME}",
                    f"Hola {newly_paid['name']}:\n\nRecibimos tu pago de {PRODUCTS[pay['product']]} "
                    f"por ${pay['amount']:,} (orden {pay['commerce_order']}).\n\n"
                    f"Ya está activo en tu cuenta.\n\nGracias por confiar en nosotros.".replace(",", "."),
                    boton=("Ir a mis códigos", f"{config.BASE_URL}/panel"))
    return pay, status


@app.post("/pago/confirmacion")
async def payment_confirmation(request: Request):
    token = str((await request.form()).get("token", ""))
    if not token:
        return PlainTextResponse("falta token", status_code=400)
    try:
        await run_in_threadpool(process_payment, token)
    except flow.FlowError:
        return PlainTextResponse("reintentar", status_code=503)  # Flow vuelve a intentar
    return PlainTextResponse("OK")


@app.api_route("/pago/retorno", methods=["GET", "POST"])
async def payment_return(request: Request):
    rate_limit(request, "retorno", limit=30)
    token = request.query_params.get("token") or str((await request.form()).get("token", ""))
    try:
        pay, status = await run_in_threadpool(process_payment, token) if token else (None, 0)
    except flow.FlowError:
        pay, status = None, flow.PENDING
    return render(request, "pago.html", user=current_user(request), pay=pay, estado=status,
                  producto=PRODUCTS.get(pay["product"], "") if pay else "")


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
            c.execute("INSERT INTO scans (qr_id, ts) VALUES (?, ?)", (q["id"], now()))
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
