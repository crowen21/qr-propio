"""Administración por línea de comandos.

  python -m app.admin usuarios              lista las cuentas
  python -m app.admin plan CORREO pro|free  cambia el plan de una cuenta
"""
import sys

from . import db


def main(argv):
    db.init()
    with db.connect() as c:
        if argv[:1] == ["usuarios"]:
            for u in c.execute("SELECT u.*, (SELECT COUNT(*) FROM qrs WHERE user_id=u.id) n FROM users u"):
                print(f"{u['email']:40} {u['plan']:5} verificado={u['verified']} qrs={u['n']} {u['name']}")
        elif len(argv) == 3 and argv[0] == "plan" and argv[2] in ("pro", "free"):
            n = c.execute("UPDATE users SET plan=? WHERE email=?", (argv[2], argv[1].lower())).rowcount
            print("Plan actualizado." if n else "No existe una cuenta con ese correo.")
        else:
            print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
