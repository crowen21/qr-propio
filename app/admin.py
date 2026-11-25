"""Administración por línea de comandos.

  python -m app.admin usuarios              lista las cuentas
  python -m app.admin plan CORREO pro|free  cambia el plan de una cuenta
  python -m app.admin aviso-cambio          muestra el correo de aviso del cambio de planes y a quiénes llegaría
  python -m app.admin aviso-cambio enviar   lo envía a todas las cuentas confirmadas (una sola vez)
"""
import sys
import time

from . import config, db, mailer

AVISO_ASUNTO = f"Cambios en los planes de {config.SITE_NAME}"


def aviso_texto(nombre: str, plazo: int) -> str:
    fin = time.strftime("%d-%m-%Y", time.localtime(plazo))
    return (
        f"Hola {nombre}:\n\n"
        f"Te escribimos para contarte un cambio en {config.SITE_NAME}.\n\n"
        f"Tus códigos actuales no cambian: se crearon con la promesa de que nunca dejarían de funcionar y la "
        f"mantenemos. Seguirán funcionando aunque no tengas un plan.\n\n"
        f"Desde el {fin}, los códigos nuevos que crees funcionarán así:\n"
        f"- Plan gratis: {config.TRIAL_DAYS} días desde el primer código.\n"
        f"- Plan Pro: mientras tengas el plan, más {config.GRACE_DAYS} días de gracia.\n"
        f"- QR permanente: pago único, no vence nunca.\n\n"
        f"Cuando termina el plazo, el código no se borra: queda en pausa y vuelve a funcionar al instante "
        f"cuando eliges un plan, sin reimprimirlo. Hasta el {fin}, los códigos nuevos que crees tampoco vencerán.\n\n"
        f"Puedes revisar los Términos de uso actualizados en {config.BASE_URL}/terminos. Si no estás de acuerdo, "
        f"puedes eliminar tu cuenta cuando quieras desde tu panel.\n\n"
        f"Cualquier duda, escríbenos a {config.CONTACTO}."
    )


def main(argv):
    db.init()
    with db.connect() as c:
        if argv[:1] == ["usuarios"]:
            for u in c.execute("SELECT u.*, (SELECT COUNT(*) FROM qrs WHERE user_id=u.id) n FROM users u"):
                print(f"{u['email']:40} {u['plan']:5} hasta={u['plan_until'] or '-'} verificado={u['verified']} qrs={u['n']} {u['name']}")
        elif len(argv) == 3 and argv[0] == "plan" and argv[2] in ("pro", "free"):
            n = c.execute("UPDATE users SET plan=?, plan_until=NULL WHERE email=?", (argv[2], argv[1].lower())).rowcount
            print("Plan actualizado." if n else "No existe una cuenta con ese correo.")
        elif argv[:1] == ["aviso-cambio"]:
            users = c.execute("SELECT * FROM users WHERE verified=1 AND grandfather_until IS NOT NULL").fetchall()
            if argv[1:] != ["enviar"]:
                print(f"Asunto: {AVISO_ASUNTO}\n\n{aviso_texto('NOMBRE', users[0]['grandfather_until'] if users else int(time.time()))}\n")
                print(f"Se enviaría a {len(users)} cuentas confirmadas. Para enviarlo: python -m app.admin aviso-cambio enviar")
                return
            ok = 0
            for u in users:
                ok += bool(mailer.send(u["email"], AVISO_ASUNTO, aviso_texto(u["name"], u["grandfather_until"]),
                                       boton=("Ver Términos", f"{config.BASE_URL}/terminos")))
            print(f"Aviso enviado a {ok} de {len(users)} cuentas.")
        else:
            print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
