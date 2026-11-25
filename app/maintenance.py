"""Tarea diaria: actualiza la lista de dominios maliciosos, vuelve a revisar todos los
enlaces activos y limpia enlaces de confirmación vencidos.

Uso:  python -m app.maintenance
"""
import logging
import time
from urllib.parse import urlsplit

import httpx

from . import config, db, mailer
from .urlcheck import check_url

log = logging.getLogger("qr.mantenimiento")


def parse_hosts(text: str) -> set[str]:
    hosts = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        item = line.split()[-1]
        host = (urlsplit(item).hostname if "://" in item else item) or ""
        host = host.lower().strip(".")
        if "." in host and host not in ("0.0.0.0", "127.0.0.1"):
            hosts.add(host)
    return hosts


def update_blocklist() -> int:
    """Descarga todas las listas. Solo reemplaza la lista guardada si TODAS se descargaron bien;
    si alguna falla se conserva la anterior y se avisa al administrador."""
    hosts: set[str] = set()
    fallas = []
    for url in config.BLOCKLIST_URLS:
        try:
            r = httpx.get(url.strip(), timeout=30, follow_redirects=True)
            r.raise_for_status()
            nuevos = parse_hosts(r.text)
            if not nuevos:
                raise ValueError("la lista llegó vacía")
            hosts |= nuevos
        except Exception as e:
            log.warning("No se pudo descargar %s: %s", url, e)
            fallas.append(f"{url}: {e}")
    with db.connect() as c:
        if hosts and not fallas:
            c.execute("DELETE FROM blocklist")
            c.executemany("INSERT OR IGNORE INTO blocklist VALUES (?)", [(h,) for h in hosts])
            return len(hosts)
        guardados = c.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0]
    log.error("Listas de sitios peligrosos con fallas; se mantiene la lista anterior (%d dominios).", guardados)
    if config.ADMIN_EMAIL:
        mailer.send(config.ADMIN_EMAIL, f"Alerta de {config.SITE_NAME}: falló la lista de sitios peligrosos",
                    "Hola:\n\nLa revisión diaria no pudo descargar estas listas:\n" + "\n".join(fallas) +
                    f"\n\nSe mantiene la lista anterior, con {guardados} dominios. "
                    "Si la lista quedó en 0, los enlaces nuevos no se están comparando con sitios peligrosos.")
    return 0


def recheck() -> tuple[int, int]:
    flagged = 0
    with db.connect() as c:
        rows = c.execute("SELECT id, target FROM qrs WHERE active=1 AND kind='url'").fetchall()
        for q in rows:
            ok, why = check_url(c, q["target"])
            # un dominio caído temporalmente no es una amenaza: solo se marca lo malicioso
            bad = not ok and ("malicios" in why or "peligroso" in why or "interna" in why)
            flagged += bad
            c.execute("UPDATE qrs SET status=?, flag_reason=?, checked_at=? WHERE id=?",
                      ("flagged" if bad else "ok", why if bad else None, int(time.time()), q["id"]))
    return len(rows), flagged


def remind_expiring() -> int:
    """Avisa por correo, una vez, a quien tiene Pro por vencer en los próximos 3 días."""
    t = int(time.time())
    with db.connect() as c:
        users = c.execute("SELECT * FROM users WHERE plan='pro' AND plan_until BETWEEN ? AND ? "
                          "AND reminded_at IS NULL", (t, t + 3 * 86400)).fetchall()
        for u in users:
            fecha = time.strftime("%d-%m-%Y", time.localtime(u["plan_until"]))
            pausa = time.strftime("%d-%m-%Y", time.localtime(u["plan_until"] + config.GRACE_DAYS * 86400))
            mailer.send(u["email"], f"Tu plan Pro de {config.SITE_NAME} vence el {fecha}",
                        f"Hola {u['name']}:\n\nTu plan Pro vence el {fecha}. Si no lo renuevas, tus códigos seguirán "
                        f"funcionando {config.GRACE_DAYS} días más y el {pausa} quedarán en pausa: quien los escanee verá "
                        f"un aviso. Los códigos permanentes no se ven afectados.\n\n"
                        f"Al renovar vuelven a funcionar al instante, sin reimprimirlos: {config.BASE_URL}/planes",
                        boton=("Renovar Pro", f"{config.BASE_URL}/planes"))
            c.execute("UPDATE users SET reminded_at=? WHERE id=?", (t, u["id"]))
    return len(users)


def remind_trial() -> int:
    """Avisa por correo, una vez, a quien tiene la prueba gratis por terminar en los próximos 5 días
    y tiene códigos que quedarían en pausa (no permanentes ni anteriores al cambio)."""
    t = int(time.time())
    with db.connect() as c:
        users = c.execute("""SELECT * FROM users u WHERE trial_until BETWEEN ? AND ? AND trial_reminded IS NULL
            AND NOT (plan='pro' AND (plan_until IS NULL OR plan_until + ? > trial_until))
            AND EXISTS (SELECT 1 FROM qrs q WHERE q.user_id=u.id AND q.paid=0 AND q.legacy=0 AND q.kind != 'wifi')""",
                          (t, t + 5 * 86400, config.GRACE_DAYS * 86400)).fetchall()
        for u in users:
            fecha = time.strftime("%d-%m-%Y", time.localtime(u["trial_until"]))
            mailer.send(u["email"], f"Tu prueba gratis de {config.SITE_NAME} termina el {fecha}",
                        f"Hola {u['name']}:\n\nTu prueba gratis termina el {fecha}. Ese día tus códigos quedarán en "
                        f"pausa: quien los escanee verá un aviso en vez de tu contenido.\n\n"
                        f"Para que sigan funcionando, elige Pro o haz permanente el código que más uses (pago único, "
                        f"no vence nunca). El código impreso es el mismo: no tienes que reimprimirlo.\n\n"
                        f"Ver planes: {config.BASE_URL}/planes", boton=("Ver planes", f"{config.BASE_URL}/planes"))
            c.execute("UPDATE users SET trial_reminded=? WHERE id=?", (t, u["id"]))
    return len(users)


def expire_ad_clicks() -> int:
    """El identificador del clic en un anuncio solo sirve 90 días (Política de privacidad, sección 5)."""
    with db.connect() as c:
        return c.execute("UPDATE users SET gclid=NULL WHERE gclid IS NOT NULL AND gclid_at < ?",
                         (int(time.time()) - 90 * 86400,)).rowcount


def main():
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    db.init()
    log.info("Dominios maliciosos cargados: %d", update_blocklist())
    total, flagged = recheck()
    log.info("Enlaces revisados: %d, bloqueados: %d", total, flagged)
    remind_expiring()
    remind_trial()
    expire_ad_clicks()
    with db.connect() as c:
        c.execute("DELETE FROM tokens WHERE expires_at < ?", (int(time.time()),))
        c.execute("DELETE FROM scans WHERE ts < ?", (int(time.time()) - 400 * 86400,))
        # cuentas que nunca confirmaron su correo en 7 días
        c.execute("DELETE FROM users WHERE verified=0 AND created_at < ?", (int(time.time()) - 7 * 86400,))


if __name__ == "__main__":
    main()
