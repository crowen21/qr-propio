#!/usr/bin/env bash
# Instala o actualiza QR Propio en Ubuntu 22.04/24.04 (EC2).
#   sudo ./deploy/instalar.sh                 -> sin dominio todavía (http por IP, solo para probar)
#   sudo ./deploy/instalar.sh midominio.cl    -> con dominio y HTTPS automático
# Se puede volver a ejecutar las veces que haga falta: no borra datos.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Ejecuta con sudo."; exit 1; }
DOMINIO="${1:-}"
ORIGEN="$(cd "$(dirname "$0")/.." && pwd)"
APP=/opt/qr-propio; DATOS=/var/lib/qr-propio; ENV=/etc/qr-propio.env

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv sqlite3 caddy curl fonts-dejavu-core

id qr >/dev/null 2>&1 || useradd --system --home "$DATOS" --shell /usr/sbin/nologin qr
mkdir -p "$APP" "$DATOS/respaldos"
rm -rf "$APP/app" "$APP/deploy"
cp -r "$ORIGEN/app" "$ORIGEN/deploy" "$ORIGEN/requirements.txt" "$APP/"
find "$APP" -name __pycache__ -type d -prune -exec rm -rf {} +
[ -d "$APP/venv" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q -r "$APP/requirements.txt"
chmod +x "$APP/deploy/respaldo.sh"
chown -R qr:qr "$DATOS"; chmod 700 "$DATOS"

# QR_URL permite fijar la dirección a mano (por ejemplo una IP elástica que se asociará después).
if [ -n "$DOMINIO" ]; then URL="https://$DOMINIO"
elif [ -n "${QR_URL:-}" ]; then URL="$QR_URL"
else URL="http://$(curl -s --max-time 5 https://checkip.amazonaws.com || echo localhost)"; fi
if [ ! -f "$ENV" ]; then
  sed "s|^QR_BASE_URL=.*|QR_BASE_URL=$URL|; s|^QR_SECRET_KEY=.*|QR_SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')|" \
    "$APP/deploy/qr-propio.env.ejemplo" > "$ENV"
elif [ -n "$DOMINIO" ]; then
  sed -i "s|^QR_BASE_URL=.*|QR_BASE_URL=$URL|" "$ENV"
fi
chown root:qr "$ENV"; chmod 640 "$ENV"

cat > /etc/systemd/system/qr-propio.service <<UNIT
[Unit]
Description=QR Propio (web)
After=network-online.target
Wants=network-online.target

[Service]
User=qr
Group=qr
WorkingDirectory=$APP
EnvironmentFile=$ENV
ExecStart=$APP/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
ReadWritePaths=$DATOS

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/qr-mantenimiento.service <<UNIT
[Unit]
Description=QR Propio: actualizar listas de sitios maliciosos y revisar enlaces

[Service]
Type=oneshot
User=qr
Group=qr
WorkingDirectory=$APP
EnvironmentFile=$ENV
ExecStart=$APP/venv/bin/python -m app.maintenance
UNIT

cat > /etc/systemd/system/qr-respaldo.service <<UNIT
[Unit]
Description=QR Propio: respaldo de la base de datos

[Service]
Type=oneshot
User=qr
Group=qr
EnvironmentFile=$ENV
ExecStart=$APP/deploy/respaldo.sh
UNIT

for t in "qr-mantenimiento 04:15" "qr-respaldo 05:00"; do set -- $t
cat > /etc/systemd/system/$1.timer <<UNIT
[Unit]
Description=$1 diario

[Timer]
OnCalendar=*-*-* $2:00
Persistent=true

[Install]
WantedBy=timers.target
UNIT
done

cat > /etc/caddy/Caddyfile <<CADDY
${DOMINIO:-:80} {
    encode gzip
    request_body {
        max_size 3MB
    }
    reverse_proxy 127.0.0.1:8000
}
CADDY

systemctl daemon-reload
systemctl enable -q --now qr-propio qr-mantenimiento.timer qr-respaldo.timer
systemctl restart qr-propio
systemctl reload caddy 2>/dev/null || systemctl restart caddy
systemctl start qr-mantenimiento.service || true   # primera carga de la lista de sitios maliciosos
sleep 2
curl -fsS http://127.0.0.1:8000/salud >/dev/null && echo "Listo: $URL" || { echo "El servicio no respondió. Revisa: journalctl -u qr-propio -n 50"; exit 1; }
