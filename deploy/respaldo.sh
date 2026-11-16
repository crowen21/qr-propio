#!/usr/bin/env bash
# Copia consistente de la base (aunque el sitio esté en uso), guarda 14 días y, si hay bucket, sube a S3.
set -euo pipefail
DATOS="${QR_DATA_DIR:-/var/lib/qr-propio}"
ARCHIVO="$DATOS/respaldos/qr-$(date +%F).db"
sqlite3 "$DATOS/qr.db" ".backup '$ARCHIVO'"
gzip -f "$ARCHIVO"
find "$DATOS/respaldos" -name 'qr-*.db.gz' -mtime +14 -delete
if [ -n "${QR_BACKUP_BUCKET:-}" ] && command -v aws >/dev/null; then
  aws s3 cp --only-show-errors "$ARCHIVO.gz" "s3://$QR_BACKUP_BUCKET/qr-propio/$(basename "$ARCHIVO").gz"
fi
