"""Makes the WHOLE Hummingbot `binance_perpetual` connector keyless via the
Usenami Signer `POST /sign/binance-request` endpoint (live, testnet-only).

Drop-in: construct the connector's auth with SignerDelegatingAuth instead of the
stock BinancePerpetualAuth. The bot then holds NO exchange key/secret — only a
Signer bearer token. Every authenticated request has its signature (and the
X-MBX-APIKEY header) produced by the enclave.

The only real override is `rest_authenticate`. It reuses the stock param-building
verbatim (`op_for` + `build_payload` below) and swaps the single local-HMAC line
for an enclave round-trip (run off the event loop). Because the enclave signs the
SAME payload string and the request's params/headers are mutated exactly as stock
BinancePerpetualAuth.rest_authenticate does, the request is byte-identical to the
stock connector (covered by an equivalence test in our suite; ask for source access).

  from signer_delegating_auth import SignerDelegatingAuth
  auth = SignerDelegatingAuth(signer_gw=GW, bearer=TOKEN, time_provider=tp)
  # ...wire `auth` where BinancePerpetualAuth(...) was constructed.

No hummingbot import at module load, so the signing seam is unit-testable without
installing Hummingbot; the connector subclass is defined lazily.
"""
from __future__ import annotations

import asyncio
import http.client
import json
import urllib.error
import urllib.request
from collections import OrderedDict
from typing import Any, Callable
from urllib.parse import urlencode, urlparse

# Binance path tail (last 2 segments, e.g. "fapi/v1/order" → "v1/order") → signer op.
PATH_TO_OP = {
    "v1/order": "order",                 # refined by HTTP method below
    "v1/allOpenOrders": "allOpenOrders",
    "v1/openOrders": "openOrders",
    "v2/account": "account",
    "v2/positionRisk": "positionRisk",
    "v1/userTrades": "userTrades",
    "v1/income": "income",
    "v1/leverage": "leverage",
    "v1/positionSide/dual": "positionMode",
    "v1/listenKey": "listenKey",
}


def op_for(method: str, url: str) -> str | None:
    """Map (method, url) → the signer op name. None if the endpoint isn't authed."""
    tail = "/".join(p for p in urlparse(url).path.split("/") if p)
    tail = "/".join(tail.split("/")[-3:]) if "positionSide" in tail else "/".join(tail.split("/")[-2:])
    op = PATH_TO_OP.get(tail)
    if op == "order":
        return {"POST": "order", "GET": "orderStatus", "DELETE": "cancel"}.get(method, "order")
    return op


def build_payload(params: dict[str, Any] | None, timestamp: int) -> tuple[OrderedDict, str]:
    """Verbatim from stock BinancePerpetualAuth.add_auth_to_params: ordered params
    + timestamp last, urlencoded. Returns (ordered_params, payload_to_sign)."""
    p = OrderedDict(params or {})
    p["timestamp"] = timestamp
    return p, urlencode(p)


def remote_sign_http(signer_gw: str, bearer: str) -> Callable[[str, str], dict]:
    """Build a `(op, payload) → {signature, api_key}` caller hitting the endpoint."""
    def _call(op: str, payload: str) -> dict:
        body = json.dumps({"key_id": "binance", "op": op, "payload": payload}).encode()
        req = urllib.request.Request(
            f"{signer_gw.rstrip('/')}/sign/binance-request", data=body, method="POST",
            headers={"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    return _call


_AUTH_CLS = None


def make_auth_class():
    """Lazily define the connector subclass (needs hummingbot importable).
    Defined once, cached at module level."""
    global _AUTH_CLS
    if _AUTH_CLS is not None:
        return _AUTH_CLS
    from hummingbot.connector.derivative.binance_perpetual.binance_perpetual_auth import (
        BinancePerpetualAuth,
    )
    from hummingbot.core.web_assistant.connections.data_types import RESTMethod, RESTRequest

    class SignerDelegatingAuth(BinancePerpetualAuth):
        def __init__(self, signer_gw: str, bearer: str, time_provider):
            # No api_key/secret on the box — placeholders; the enclave supplies both.
            super().__init__(api_key="", api_secret="", time_provider=time_provider)
            self._remote_sign = remote_sign_http(signer_gw, bearer)

        async def rest_authenticate(self, request: RESTRequest) -> RESTRequest:
            method = request.method.value if hasattr(request.method, "value") else str(request.method)
            op = op_for(method, request.url)
            if op is None:
                # Every authenticated binance_perpetual endpoint is mapped in
                # PATH_TO_OP (covered by a mapping test in our suite). An
                # unmapped path means a NEW/unexpected endpoint — fail loudly
                # rather than send the enclave a null op.
                raise ValueError(f"no signer op mapped for {method} {request.url} — refusing to sign")
            # Mirror stock BinancePerpetualAuth exactly (REF line 30): POST params
            # come from the JSON body, GET from request.params.
            src = json.loads(request.data) if (request.method == RESTMethod.POST and request.data is not None) else request.params
            ts = int(self._time_provider.time() * 1e3)
            params, payload = build_payload(src, ts)
            # The signing call blocks (urllib); run it OFF the event loop so a
            # slow enclave round-trip can't stall the connector. Translate
            # transport/enclave failures into a clear auth error.
            loop = asyncio.get_running_loop()
            try:
                resp = await loop.run_in_executor(None, self._remote_sign, op, payload)
            except urllib.error.HTTPError as e:
                raise RuntimeError(f"signer denied/failed op {op!r}: HTTP {e.code}") from e
            except (OSError, http.client.HTTPException, json.JSONDecodeError) as e:
                # OSError covers URLError, ssl.SSLError, socket timeouts; keep the
                # wrap-contract: transport failures surface as a clear RuntimeError.
                raise RuntimeError(f"signer request failed for op {op!r}: {e}") from e
            if (not isinstance(resp, dict)
                    or not isinstance(resp.get("signature"), str) or not resp["signature"]
                    or not isinstance(resp.get("api_key"), str) or not resp["api_key"]):
                raise RuntimeError(f"signer response for op {op!r} missing signature/api_key")
            params["signature"] = resp["signature"]
            # request.data/params + the header overwrite mirror stock exactly
            # (REF lines 30-34) so the request is byte-identical to the stock
            # connector — the whole point of the drop-in.
            if request.method == RESTMethod.POST:
                request.data = params
            else:
                request.params = params
            request.headers = {"X-MBX-APIKEY": resp["api_key"]}    # ← api key returned transiently
            return request

    _AUTH_CLS = SignerDelegatingAuth
    return _AUTH_CLS


# Convenience for real use once hummingbot is installed.
def SignerDelegatingAuth(*args, **kwargs):  # noqa: N802 (facade over the lazy class)
    return make_auth_class()(*args, **kwargs)
