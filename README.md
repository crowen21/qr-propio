# QR Propio

Generador de códigos QR dinámicos autoalojado: cuentas con correo verificado, códigos que no
caducan, destino editable, revisión de seguridad de enlaces y logo al centro para el plan de pago.

## Tipos de código

| Tipo | Cómo funciona |
|---|---|
| Página web, WhatsApp, Instagram, Ubicación | El QR pasa por el sitio y redirige. Editable y con conteo de escaneos. |
| Llamada, SMS, Correo, Contacto, Texto | El QR abre una página del sitio con el contenido y un botón. Editable y con conteo. |
| WiFi | Los datos van dentro del QR. Funciona sin internet, pero no se cuenta ni se edita sin reimprimir. |

Para agregar un tipo nuevo basta con declararlo en `app/kinds.py`.

## Instalar en una instancia EC2 nueva (Ubuntu 24.04)

1. Crea la instancia (t3.micro o t4g.micro basta), asígnale una **IP elástica** y abre solo los
   puertos 22 (tu IP), 80 y 443.
2. Copia esta carpeta al servidor y ejecuta:

       sudo ./deploy/instalar.sh                # todavía sin dominio: prueba por http://IP
       sudo ./deploy/instalar.sh midominio.cl   # cuando el dominio ya apunte a la IP: activa HTTPS

   El segundo comando se puede ejecutar después sobre la misma instalación; no borra datos.

## Ingreso con Google y Microsoft

Requiere el dominio con HTTPS ya funcionando (Google no acepta direcciones IP).

- **Google:** Google Cloud Console → APIs y servicios → Credenciales → Crear ID de cliente de OAuth
  (aplicación web). URI de redireccionamiento autorizado: `https://TU-DOMINIO/entrar/google/retorno`.
- **Microsoft:** centro de administración de Microsoft Entra → Registros de aplicaciones → Nuevo
  registro, con cuentas de cualquier organización y cuentas personales. URI de redirección (Web):
  `https://TU-DOMINIO/entrar/microsoft/retorno`. Luego crea un secreto de cliente; vence, así que
  anota la fecha para renovarlo.

Copia los ID y secretos en `/etc/qr-propio.env` y reinicia el servicio.

Con Google el correo llega verificado y la cuenta entra directo. Con Microsoft el correo no viene
garantizado, por eso la primera vez se confirma con un enlace al correo.

## Importante antes de imprimir un QR

Cada QR lleva adentro la dirección del sitio (`QR_BASE_URL`). Los códigos creados mientras el sitio
funciona por IP dejarán de servir si la IP cambia. Crea los códigos definitivos **después** de
configurar el dominio.

## Operación

| Qué | Cómo |
|---|---|
| Configuración | `/etc/qr-propio.env`, luego `sudo systemctl restart qr-propio` |
| Ver registros | `journalctl -u qr-propio -f` |
| Listar cuentas | `cd /opt/qr-propio && sudo -u qr env $(sudo grep -v '^#' /etc/qr-propio.env \| xargs) venv/bin/python -m app.admin usuarios` |
| Pasar una cuenta a Pro | igual que arriba, con `plan correo@ejemplo.cl pro` |
| Respaldos | diarios en `/var/lib/qr-propio/respaldos` (14 días) y en S3 si defines `QR_BACKUP_BUCKET` |
| Restaurar | detener el servicio, `gunzip` del respaldo sobre `/var/lib/qr-propio/qr.db`, iniciar |
| Revisión de enlaces | diaria, `systemctl start qr-mantenimiento` para forzarla |

## Correos

Con el SMTP configurado, cada código nuevo se envía como imagen PNG al correo de su dueño, y el
panel tiene un botón «Enviar a mi correo». Solo se envía al correo de la propia cuenta.

## Seguridad incluida

- Claves con scrypt, sesiones firmadas, protección CSRF, límite de intentos por IP.
- Correo verificado antes de poder ingresar; no se revela qué correos están registrados.
- Enlaces: solo http/https, sin credenciales incrustadas, sin destinos a redes internas, lista
  URLhaus actualizada a diario y Google Safe Browsing opcional. Un código cuyo destino se vuelve
  malicioso deja de redirigir y muestra una advertencia.
- Logos: se validan y se vuelven a codificar como PNG; no se aceptan SVG.
- Sin JavaScript en el sitio (CSP `script-src 'none'`), servicio systemd con permisos mínimos.

## Pruebas

    pip install -r requirements.txt pytest opencv-python-headless
    python -m pytest tests
