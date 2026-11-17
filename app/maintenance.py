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
            mailer.send(u["email"], f"Tu plan Pro de {config.SITE_NAME} vence el {fecha}",
                        f"Hola {u['name']}:\n\nTu plan Pro vence el {fecha}. Tus códigos van a seguir funcionando "
                        f"igual, pero dejarás de poder editarlos y cambiar su diseño.\n\n"
                        f"Para renovarlo: {config.BASE_URL}/planes", boton=("Renovar Pro", f"{config.BASE_URL}/planes"))
            c.execute("UPDATE users SET reminded_at=? WHERE id=?", (t, u["id"]))
    return len(users)


def main():
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    db.init()
    log.info("Dominios maliciosos cargados: %d", update_blocklist())
    total, flagged = recheck()
    log.info("Enlaces revisados: %d, bloqueados: %d", total, flagged)
    remind_expiring()
    with db.connect() as c:
        c.execute("DELETE FROM tokens WHERE expires_at < ?", (int(time.time()),))
        c.execute("DELETE FROM scans WHERE ts < ?", (int(time.time()) - 400 * 86400,))
        # cuentas que nunca confirmaron su correo en 7 días
        c.execute("DELETE FROM users WHERE verified=0 AND created_at < ?", (int(time.time()) - 7 * 86400,))


if __name__ == "__main__":
    main()
