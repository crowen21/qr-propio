import io, os, re, tempfile
os.environ["QR_DATA_DIR"] = tempfile.mkdtemp()
os.environ["QR_BASE_URL"] = "http://testserver"

import cv2, numpy as np, pytest
from fastapi.testclient import TestClient
from PIL import Image
from app import db, mailer, urlcheck, maintenance
from app.main import app, _hits

urlcheck.resolve = lambda h: {"interno.example.com": ["10.0.0.5"], "noexiste.example.com": []}.get(h, ["93.184.216.34"])


def csrf(c, path="/ingresar"):
    return re.search(r'name="csrf" value="([^"]+)"', c.get(path).text).group(1)


def last_link():
    return re.search(r"http://testserver(/\S+)", mailer.outbox[-1][2]).group(1)


def signup(c, email="ana@example.com", pw="clave-segura-123"):
    r = c.post("/registro", data={"name": "Ana Pérez", "email": email, "password": pw, "csrf": csrf(c, "/registro")})
    assert r.status_code == 200 and "Revisa tu correo" in r.text
    assert c.get(last_link(), follow_redirects=False).status_code == 303
    r = c.post("/ingresar", data={"email": email, "password": pw, "csrf": csrf(c)}, follow_redirects=False)
    assert r.status_code == 303
    return c


@pytest.fixture
def c():
    _hits.clear(); mailer.outbox.clear()
    with db.connect() as conn:
        for t in ("users", "qrs", "tokens", "blocklist"):
            conn.execute(f"DELETE FROM {t}")
    return TestClient(app)


def new_qr(c, target, name="Menú"):
    return c.post("/qr/nuevo", data={"kind": "url", "name": name, "target": target, "csrf": csrf(c, "/qr/nuevo")})


def make(c, kind, **fields):
    r = c.post("/qr/nuevo", data={"kind": kind, "name": "Prueba", "csrf": csrf(c, "/qr/nuevo"), **fields})
    assert r.status_code == 200, re.search(r'role="alert">([^<]+)', r.text).group(1)
    qid = re.findall(r"/qr/(\d+)/editar", r.text)[0]
    with db.connect() as conn:
        return conn.execute("SELECT * FROM qrs WHERE id=?", (qid,)).fetchone()


def code_of(c):
    return re.search(r"/r/([a-z0-9]{7})", c.get("/panel").text).group(1)


def decode(png):
    img = cv2.imdecode(np.frombuffer(png, np.uint8), cv2.IMREAD_COLOR)
    return cv2.QRCodeDetector().detectAndDecode(img)[0]


def test_login_requires_verification(c):
    c.post("/registro", data={"name": "Ana Pérez", "email": "a@example.com", "password": "clave-segura-123", "csrf": csrf(c, "/registro")})
    r = c.post("/ingresar", data={"email": "a@example.com", "password": "clave-segura-123", "csrf": csrf(c)})
    assert r.status_code == 403 and "confirmar" in r.text
    assert c.get("/panel", follow_redirects=False).headers["location"] == "/ingresar"


def test_wrong_password_and_csrf(c):
    signup(c); c.cookies.clear()
    assert c.post("/ingresar", data={"email": "ana@example.com", "password": "mala", "csrf": csrf(c)}).status_code == 401
    assert c.post("/ingresar", data={"email": "ana@example.com", "password": "clave-segura-123", "csrf": "x"}).status_code == 403


def test_weak_password_rejected(c):
    r = c.post("/registro", data={"name": "Ana", "email": "a@example.com", "password": "corta", "csrf": csrf(c, "/registro")})
    assert r.status_code == 400


def test_duplicate_email_not_revealed(c):
    signup(c); c.cookies.clear()
    r = c.post("/registro", data={"name": "Otro", "email": "ana@example.com", "password": "otra-clave-larga", "csrf": csrf(c, "/registro")})
    assert "Revisa tu correo" in r.text and "Ya tienes una cuenta" in mailer.outbox[-1][1]


def test_qr_lifecycle(c):
    signup(c)
    assert new_qr(c, "ejemplo.cl/menu").status_code == 200
    code = code_of(c)
    r = c.get(f"/r/{code}", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "https://ejemplo.cl/menu"
    assert "1 escaneos" in c.get("/panel").text
    qid = re.search(r"/qr/(\d+)/editar", c.get("/panel").text).group(1)
    png = c.get(f"/qr/{qid}/imagen.png").content
    assert decode(png) == f"http://testserver/r/{code}"
    assert c.get(f"/qr/{qid}/imagen.svg").text.lstrip().startswith("<?xml")
    # cambiar destino: mismo código, otro destino
    c.post(f"/qr/{qid}/editar", data={"name": "Menú", "target": "https://otro.cl/x", "csrf": csrf(c, "/panel")})
    assert c.get(f"/r/{code}", follow_redirects=False).headers["location"] == "https://otro.cl/x"
    # pausar
    c.post(f"/qr/{qid}/estado", data={"csrf": csrf(c, "/panel")})
    assert c.get(f"/r/{code}").status_code == 404


@pytest.mark.parametrize("url", [
    "javascript:alert(1)", "ftp://example.com/x", "http://127.0.0.1/admin", "http://169.254.169.254/latest",
    "http://[::1]/", "https://banco.cl@malo.example.com/", "http://interno.example.com/", "http://noexiste.example.com/",
    "http://testserver/r/abc", "http://localhost/", "https://exa mple.com",
])
def test_bad_urls_blocked(c, url):
    signup(c)
    assert new_qr(c, url).status_code == 400
    assert "/r/" not in c.get("/panel").text


def test_blocklist_and_recheck(c):
    signup(c)
    with db.connect() as conn:
        conn.execute("INSERT INTO blocklist VALUES ('malware.example.net')")
    assert new_qr(c, "https://sub.malware.example.net/x").status_code == 400
    # un destino que se vuelve malicioso después de creado
    assert new_qr(c, "https://luego-malo.example.org/").status_code == 200
    code = code_of(c)
    with db.connect() as conn:
        conn.execute("INSERT INTO blocklist VALUES ('luego-malo.example.org')")
    assert maintenance.recheck() == (1, 1)
    r = c.get(f"/r/{code}", follow_redirects=False)
    assert r.status_code == 403 and "Detuvimos" in r.text
    assert "Bloqueado por seguridad" in c.get("/panel").text


def test_isolation_between_users(c):
    signup(c); new_qr(c, "https://ejemplo.cl")
    qid = re.search(r"/qr/(\d+)/editar", c.get("/panel").text).group(1)
    c2 = signup(TestClient(app), email="beto@example.com")
    assert c2.get(f"/qr/{qid}/imagen.png").status_code == 404
    assert c2.post(f"/qr/{qid}/eliminar", data={"csrf": csrf(c2, "/panel")}).status_code == 404
    assert TestClient(app).get(f"/qr/{qid}/imagen.png").status_code == 401


def logo_png(color="red"):
    b = io.BytesIO(); Image.new("RGB", (500, 300), color).save(b, "PNG"); return b.getvalue()


def test_logo_is_pro_only_and_still_scans(c):
    signup(c); new_qr(c, "https://ejemplo.cl/una/ruta/larga")
    qid = re.search(r"/qr/(\d+)/editar", c.get("/panel").text).group(1)
    data = {"name": "Menú", "target": "https://ejemplo.cl/una/ruta/larga", "csrf": csrf(c, "/panel")}
    assert c.post(f"/qr/{qid}/editar", data=data, files={"logo": ("l.png", logo_png(), "image/png")}).status_code == 400
    with db.connect() as conn:
        conn.execute("UPDATE users SET plan='pro'")
    assert c.post(f"/qr/{qid}/editar", data=data, files={"logo": ("x.png", b"<svg onload=alert(1)>", "image/png")}).status_code == 400
    assert c.post(f"/qr/{qid}/editar", data=data, files={"logo": ("l.png", logo_png(), "image/png")}).status_code == 200
    png = c.get(f"/qr/{qid}/imagen.png").content
    img = Image.open(io.BytesIO(png)).convert("RGB")
    assert img.getpixel((img.width // 2, img.height // 2)) == (255, 0, 0)
    assert decode(png) == f"http://testserver/r/{code_of(c)}"
    assert "data:image/png;base64" in c.get(f"/qr/{qid}/imagen.svg").text


def test_password_reset_invalidates_session(c):
    signup(c)
    other = TestClient(app)
    other.post("/recuperar", data={"email": "ana@example.com", "csrf": csrf(other, "/recuperar")})
    link = last_link(); token = link.split("token=")[1]
    other.post("/restablecer", data={"token": token, "password": "clave-nueva-456", "csrf": csrf(other, link)})
    assert c.get("/panel", follow_redirects=False).status_code == 303  # sesión antigua ya no sirve
    assert other.post("/restablecer", data={"token": token, "password": "clave-nueva-789", "csrf": csrf(other)}).status_code == 400


def test_delete_account(c):
    signup(c); new_qr(c, "https://ejemplo.cl"); code = code_of(c)
    assert c.post("/cuenta/eliminar", data={"password": "mala", "csrf": csrf(c, "/panel")}).status_code == 400
    assert "eliminada" in c.post("/cuenta/eliminar", data={"password": "clave-segura-123", "csrf": csrf(c, "/panel")}).text
    assert c.get(f"/r/{code}").status_code == 404


def test_rate_limit(c):
    for _ in range(10):
        c.post("/ingresar", data={"email": "x@example.com", "password": "y", "csrf": csrf(c)})
    assert c.post("/ingresar", data={"email": "x@example.com", "password": "y", "csrf": csrf(c)}).status_code == 429


def test_headers(c):
    h = c.get("/").headers
    assert "script-src 'none'" in h["content-security-policy"] and h["x-frame-options"] == "DENY"


def test_parse_hosts():
    assert maintenance.parse_hosts("# c\n127.0.0.1\tbad.example.com\nhttp://evil.example.org/a.exe\n") == {"bad.example.com", "evil.example.org"}


def test_whatsapp(c):
    signup(c)
    q = make(c, "whatsapp", phone="9 1234 5678", message="Hola, ¿tienen hora?")
    r = c.get(f"/r/{q['code']}", follow_redirects=False)
    assert r.headers["location"] == "https://wa.me/56912345678?text=Hola%2C%20%C2%BFtienen%20hora%3F"
    r = c.post("/qr/nuevo", data={"kind": "whatsapp", "name": "x", "phone": "123", "csrf": csrf(c, "/qr/nuevo")})
    assert r.status_code == 400 and "código de país" in r.text


def test_instagram_and_map(c):
    signup(c)
    q = make(c, "instagram", username="@mi.tienda_cl")
    assert c.get(f"/r/{q['code']}", follow_redirects=False).headers["location"] == "https://www.instagram.com/mi.tienda_cl/"
    assert c.post("/qr/nuevo", data={"kind": "instagram", "name": "x", "username": "a/../b", "csrf": csrf(c, "/qr/nuevo")}).status_code == 400
    q = make(c, "ubicacion", query="Av. Macul 123, Santiago")
    assert c.get(f"/r/{q['code']}", follow_redirects=False).headers["location"].endswith("query=Av.%20Macul%20123%2C%20Santiago")


def test_landing_pages(c):
    signup(c)
    q = make(c, "tel", phone="+56 2 2345 6789")
    assert 'href="tel:+56223456789"' in c.get(f"/r/{q['code']}").text
    q = make(c, "sms", phone="912345678", message="Quiero reservar")
    assert 'href="sms:+56912345678?&amp;body=Quiero%20reservar"' in c.get(f"/r/{q['code']}").text
    q = make(c, "email", to="hola@ejemplo.cl", subject="Cotización", body="Hola")
    assert 'href="mailto:hola@ejemplo.cl?subject=Cotizaci%C3%B3n&amp;body=Hola"' in c.get(f"/r/{q['code']}").text
    q = make(c, "texto", text="<script>alert(1)</script>\nLínea 2")
    page = c.get(f"/r/{q['code']}").text
    assert "&lt;script&gt;" in page and "<script>alert" not in page
    assert "4 escaneos" not in c.get("/panel").text and "1 escaneos" in c.get("/panel").text


def test_vcard(c):
    signup(c)
    q = make(c, "vcard", full_name="Ana Pérez; Soto", phone="912345678", email="ana@ejemplo.cl", org="Mi Empresa", title="Gerenta", website="ejemplo.cl")
    assert "Guardar contacto" in c.get(f"/r/{q['code']}").text
    r = c.get(f"/r/{q['code']}/contacto.vcf")
    assert r.headers["content-type"].startswith("text/vcard")
    assert "FN:Ana Pérez\\; Soto\r\n" in r.text and "TEL;TYPE=CELL:+56912345678" in r.text and "URL:https://ejemplo.cl" in r.text
    assert c.post("/qr/nuevo", data={"kind": "vcard", "name": "x", "full_name": "A B", "website": "javascript:alert(1)//://", "csrf": csrf(c, "/qr/nuevo")}).status_code == 400


def test_wifi_is_static(c):
    signup(c)
    q = make(c, "wifi", ssid="Casa;Lira", security="WPA", password='cla:ve"123')
    assert decode(c.get(f"/qr/{q['id']}/imagen.png").content) == 'WIFI:T:WPA;S:Casa\\;Lira;P:cla\\:ve\\"123;;'
    assert c.get(f"/r/{q['code']}").status_code == 404
    assert c.post("/qr/nuevo", data={"kind": "wifi", "name": "x", "ssid": "Red", "security": "WPA", "password": "corta", "csrf": csrf(c, "/qr/nuevo")}).status_code == 400
    q = make(c, "wifi", ssid="Abierta", security="nopass", password="loquesea")
    assert decode(c.get(f"/qr/{q['id']}/imagen.png").content) == "WIFI:T:nopass;S:Abierta;;"


def test_edit_keeps_kind_and_code(c):
    signup(c)
    q = make(c, "whatsapp", phone="912345678", message="")
    r = c.post(f"/qr/{q['id']}/editar", data={"kind": "url", "name": "Otro", "phone": "+56 9 8765 4321", "target": "https://malo.example", "csrf": csrf(c, "/panel")})
    assert r.status_code == 200
    assert c.get(f"/r/{q['code']}", follow_redirects=False).headers["location"] == "https://wa.me/56987654321"
    assert 'value="+56987654321"' in c.get(f"/qr/{q['id']}/editar").text


def test_unknown_kind(c):
    signup(c)
    assert c.get("/qr/nuevo?tipo=xyz").status_code == 404
    assert c.post("/qr/nuevo", data={"kind": "xyz", "name": "x", "csrf": csrf(c, "/qr/nuevo")}).status_code == 400


# ---------- ingreso con Google / Microsoft ----------
import base64, json, time
from urllib.parse import parse_qs, urlsplit
from app import oauth

for _p in oauth.PROVIDERS.values():
    _p.update(client_id="cid", secret="sec")
MS_TID = "9188040d-6c67-4c5b-b112-36a304b66dad"


class FakeResp:
    def __init__(self, claims): self.claims = claims
    def raise_for_status(self): pass
    def json(self):
        b = base64.urlsafe_b64encode(json.dumps(self.claims).encode()).rstrip(b"=").decode()
        return {"id_token": f"x.{b}.y"}


def oauth_login(c, provider, monkeypatch, **claims):
    r = c.get(f"/entrar/{provider}", follow_redirects=False)
    q = parse_qs(urlsplit(r.headers["location"]).query)
    assert q["code_challenge_method"] == ["S256"] and q["redirect_uri"] == [f"http://testserver/entrar/{provider}/retorno"]
    base = {"aud": "cid", "exp": time.time() + 300, "nonce": q["nonce"][0], "sub": "s1", "name": "Ana Pérez"}
    base.update({"iss": "https://accounts.google.com", "email_verified": True} if provider == "google"
                else {"iss": f"https://login.microsoftonline.com/{MS_TID}/v2.0", "tid": MS_TID})
    base.update(claims)
    sent = {}
    monkeypatch.setattr(oauth.httpx, "post", lambda url, **kw: sent.update(kw["data"]) or FakeResp(base))
    state = claims.pop("_state", None) or q["state"][0]
    r = c.get(f"/entrar/{provider}/retorno?code=abc&state={state}", follow_redirects=False)
    return r, sent


def test_google_new_user(c, monkeypatch):
    r, sent = oauth_login(c, "google", monkeypatch, email="Ana@Gmail.com")
    assert r.status_code == 303 and r.headers["location"] == "/panel" and sent["code_verifier"]
    assert "Ana Pérez" in c.get("/panel").text and not mailer.outbox
    assert "Escribe tu correo" in c.get("/panel").text
    c.cookies.clear()  # vuelve otro día: misma cuenta
    oauth_login(c, "google", monkeypatch, email="ana@gmail.com")
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
    assert "eliminada" in c.post("/cuenta/eliminar", data={"confirm_email": "ana@gmail.com", "csrf": csrf(c, "/panel")}).text


def test_google_links_existing_account(c, monkeypatch):
    signup(c); new_qr(c, "https://ejemplo.cl"); c.cookies.clear()
    r, _ = oauth_login(c, "google", monkeypatch, email="ana@example.com")
    assert r.headers["location"] == "/panel" and "1 de 50" in c.get("/panel").text


def test_google_takes_over_unverified_squatter(c, monkeypatch):
    # un tercero registró el correo de la víctima con su propia clave, sin confirmarlo
    c.post("/registro", data={"name": "Intruso", "email": "ana@example.com", "password": "clave-del-intruso", "csrf": csrf(c, "/registro")})
    oauth_login(c, "google", monkeypatch, email="ana@example.com")
    other = TestClient(app)
    assert other.post("/ingresar", data={"email": "ana@example.com", "password": "clave-del-intruso", "csrf": csrf(other)}).status_code == 401
    assert other.get(last_link(), follow_redirects=False).status_code == 400  # su enlace de confirmación ya no sirve


@pytest.mark.parametrize("bad", [{"aud": "otro"}, {"nonce": "x"}, {"exp": 1}, {"iss": "https://evil.example"}, {"_state": "falso"}])
def test_oauth_rejects_tampering(c, monkeypatch, bad):
    r, _ = oauth_login(c, "google", monkeypatch, email="ana@gmail.com", **bad)
    assert r.status_code == 400 and c.get("/panel", follow_redirects=False).status_code == 303


def test_google_unverified_email_needs_confirmation(c, monkeypatch):
    r, _ = oauth_login(c, "google", monkeypatch, email="ana@corp.example", email_verified=False)
    assert "Revisa tu correo" in r.text and c.get("/panel", follow_redirects=False).status_code == 303


def test_microsoft_confirms_email_once(c, monkeypatch):
    r, _ = oauth_login(c, "microsoft", monkeypatch, email="ana@outlook.com")
    assert r.status_code == 200 and "Revisa tu correo" in r.text
    assert c.get("/panel", follow_redirects=False).headers["location"] == "/ingresar"
    c.get(last_link())
    r, _ = oauth_login(c, "microsoft", monkeypatch, email="ana@outlook.com")
    assert r.headers["location"] == "/panel"


def test_microsoft_cannot_claim_existing_email(c, monkeypatch):
    signup(c); new_qr(c, "https://ejemplo.cl"); c.cookies.clear()
    r, _ = oauth_login(c, "microsoft", monkeypatch, email="ana@example.com")  # correo afirmado por otro tenant
    assert "Revisa tu correo" in r.text and c.get("/panel", follow_redirects=False).status_code == 303
    assert "Intento de ingreso" in mailer.outbox[-1][1]
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM identities").fetchone()[0] == 0


def test_microsoft_issuer_must_match_tenant(c, monkeypatch):
    r, _ = oauth_login(c, "microsoft", monkeypatch, email="a@b.cl", iss="https://login.microsoftonline.com/otro/v2.0")
    assert r.status_code == 400


def test_buttons_only_when_configured(c, monkeypatch):
    assert "Continuar con Microsoft" in c.get("/").text
    assert "Continuar con Google" in c.get("/ingresar").text and "Continuar con Microsoft" in c.get("/registro").text
    monkeypatch.setitem(oauth.PROVIDERS["google"], "secret", "")
    assert "Continuar con Google" not in c.get("/ingresar").text
    assert c.get("/entrar/google", follow_redirects=False).status_code == 404


# ---------- QR por correo ----------
class FakeSMTP:
    sent = []
    def __init__(self, *a, **k): pass
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def starttls(self): pass
    def login(self, *a): pass
    def send_message(self, msg): FakeSMTP.sent.append(msg)


def test_qr_is_emailed_to_owner_only(c, monkeypatch):
    signup(c); other = signup(TestClient(app), email="beto@example.com")
    FakeSMTP.sent.clear()
    monkeypatch.setattr(mailer.config, "SMTP_HOST", "smtp.test"); monkeypatch.setattr(mailer.config, "SMTP_FROM", "qr@test.cl")
    monkeypatch.setattr(mailer.smtplib, "SMTP", FakeSMTP)
    r = c.post("/qr/nuevo", data={"kind": "whatsapp", "name": "Vitrina", "phone": "912345678", "csrf": csrf(c, "/qr/nuevo")})
    assert "Te lo enviamos a ana@example.com" in r.text
    msg = FakeSMTP.sent[-1]
    assert msg["To"] == "ana@example.com" and "Vitrina" in msg["Subject"]
    att = [p for p in msg.iter_attachments()][0]
    assert att.get_content_type() == "image/png" and decode(att.get_content()) == f"http://testserver/r/{code_of(c)}"
    qid = re.search(r"/qr/(\d+)/correo", r.text).group(1)
    r = c.post(f"/qr/{qid}/correo", data={"csrf": csrf(c, "/panel"), "email": "otro@victima.cl"})
    assert len(FakeSMTP.sent) == 2 and FakeSMTP.sent[-1]["To"] == "ana@example.com"
    assert other.post(f"/qr/{qid}/correo", data={"csrf": csrf(other, "/panel")}).status_code == 404


def test_email_failure_is_reported(c):
    signup(c); new_qr(c, "https://ejemplo.cl")  # sin SMTP configurado
    qid = re.search(r"/qr/(\d+)/correo", c.get("/panel").text).group(1)
    assert "No pudimos enviar" in c.post(f"/qr/{qid}/correo", data={"csrf": csrf(c, "/panel")}).text
