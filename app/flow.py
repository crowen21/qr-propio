"""Cliente mínimo de la API de pagos de Flow (flow.cl).

Cada solicitud se firma con HMAC-SHA256: se ordenan los parámetros por nombre, se concatena
nombre+valor sin separadores y se firma con la clave secreta; la firma va en el parámetro "s".
Nunca se confía en lo que llega por el navegador: el estado del pago siempre se consulta a Flow.
"""
import hashlib
import hmac

import httpx

from . import config

PENDING, PAID, REJECTED, CANCELLED = 1, 2, 3, 4


class FlowError(Exception):
    pass


def _check(r: httpx.Response) -> dict:
    if r.status_code >= 400:  # Flow explica el motivo en el cuerpo: se guarda en el registro
        raise FlowError(f"HTTP {r.status_code}: {r.text[:300]}")
    return r.json()


def enabled() -> bool:
    return bool(config.FLOW_API_KEY and config.FLOW_SECRET)


def sign(params: dict) -> str:
    text = "".join(f"{k}{params[k]}" for k in sorted(params))
    return hmac.new(config.FLOW_SECRET.encode(), text.encode(), hashlib.sha256).hexdigest()


def _signed(params: dict) -> dict:
    params = {"apiKey": config.FLOW_API_KEY, **params}
    return {**params, "s": sign(params)}


def create_payment(order: str, subject: str, amount: int, email: str) -> tuple[str, str]:
    """Crea el pago y devuelve (url a la que se envía al cliente, token)."""
    try:
        r = httpx.post(f"{config.FLOW_API_URL}/payment/create", timeout=15, data=_signed({
            "commerceOrder": order, "subject": subject, "currency": "CLP", "amount": amount,
            "email": email, "urlConfirmation": f"{config.BASE_URL}/pago/confirmacion",
            "urlReturn": f"{config.BASE_URL}/pago/retorno",
        }))
        body = _check(r)
        return f"{body['url']}?token={body['token']}", body["token"]
    except Exception as e:
        raise FlowError(f"Flow no respondió al crear el pago: {e}") from e


def payment_status(token: str) -> dict:
    try:
        r = httpx.get(f"{config.FLOW_API_URL}/payment/getStatus", timeout=15,
                      params=_signed({"token": token}))
        return _check(r)
    except Exception as e:
        raise FlowError(f"Flow no respondió al consultar el pago: {e}") from e
