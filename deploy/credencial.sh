#!/usr/bin/env bash
# Guarda credenciales en /etc/qr-propio.env sin que queden en pantalla ni en el historial.
#   sudo bash deploy/credencial.sh QR_GOOGLE_CLIENT_ID QR_GOOGLE_CLIENT_SECRET
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Ejecuta con sudo."; exit 1; }
ENV=/etc/qr-propio.env
for VAR in "$@"; do
  [[ "$VAR" =~ ^QR_[A-Z_]+$ ]] || { echo "Nombre no válido: $VAR"; exit 1; }
  read -r -s -p "Pega el valor de $VAR y presiona Enter: " VAL; echo
  VAL="$(printf '%s' "$VAL" | tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [ -n "$VAL" ] || { echo "Valor vacío; no se guardó $VAR."; exit 1; }
  [[ "$VAL" != *'|'* ]] || { echo "El valor contiene un carácter no permitido."; exit 1; }
  grep -q "^$VAR=" "$ENV" || echo "$VAR=" >> "$ENV"
  sed -i "s|^$VAR=.*|$VAR=$VAL|" "$ENV"
  echo "$VAR guardada (${#VAL} caracteres)."
done
systemctl restart qr-propio && sleep 2 && curl -fsS http://127.0.0.1:8000/salud >/dev/null && echo "Servicio reiniciado."
