#!/usr/bin/env bash
# Guarda credenciales en /etc/qr-propio.env sin que queden en pantalla ni en el historial.
#   sudo bash deploy/credencial.sh QR_GOOGLE_CLIENT_ID QR_GOOGLE_CLIENT_SECRET
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Ejecuta con sudo."; exit 1; }
ENV=/etc/qr-propio.env
for VAR in "$@"; do
  [[ "$VAR" =~ ^QR_[A-Z_]+$ ]] || { echo "Nombre no válido: $VAR"; exit 1; }
  read -r -s -p "Pega el valor de $VAR y presiona Enter: " VAL || true; echo
  VAL="$(printf '%s' "$VAL" | tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  # La terminal web a veces pega el texto varias veces seguidas: se toma la primera copia con el formato esperado.
  case "$VAR" in
    QR_GOOGLE_CLIENT_ID) PATRON='[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com' ;;
    QR_GOOGLE_CLIENT_SECRET) PATRON='GOCSPX-[A-Za-z0-9_-]{28}' ;;
    QR_MS_CLIENT_ID) PATRON='[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' ;;
    *) PATRON='' ;;
  esac
  if [ -n "$PATRON" ]; then
    VAL="$(printf '%s' "$VAL" | grep -oE "$PATRON" | head -n1 || true)"
  fi
  [ -n "$VAL" ] || { echo "No encontré un valor válido para $VAR; no se guardó. Vuelve a intentarlo."; exit 1; }
  [[ "$VAL" != *'|'* ]] || { echo "El valor contiene un carácter no permitido."; exit 1; }
  grep -q "^$VAR=" "$ENV" || echo "$VAR=" >> "$ENV"
  sed -i "s|^$VAR=.*|$VAR=$VAL|" "$ENV"
  echo "$VAR guardada (${#VAL} caracteres)."
done
systemctl restart qr-propio && sleep 2 && curl -fsS http://127.0.0.1:8000/salud >/dev/null && echo "Servicio reiniciado."
