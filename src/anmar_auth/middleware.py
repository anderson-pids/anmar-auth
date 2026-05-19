import base64
from typing import Optional
from urllib.parse import quote

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse

from anmar_auth.exceptions import TokenInvalidError
from anmar_auth.jwks_cache import JWKSCache


def _b64url_to_int(s: str) -> int:
    pad = "=" * (-len(s) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(s + pad), "big")


def _jwk_to_pubkey(jwk: dict):
    n = _b64url_to_int(jwk["n"])
    e = _b64url_to_int(jwk["e"])
    return RSAPublicNumbers(e, n).public_key()


class AnmarAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, jwks_url: str, issuer: str, cookie_name: str = "anmar_session", jwks_ttl: int = 3600):
        super().__init__(app)
        self._cache = JWKSCache(jwks_url, ttl=jwks_ttl)
        self._issuer = issuer
        self._cookie_name = cookie_name

    async def dispatch(self, request: Request, call_next):
        token = self._extract_token(request)
        if token:
            try:
                claims = await self._verify(token)
                request.state.user = claims
            except TokenInvalidError:
                request.state.user = None
        else:
            request.state.user = None
        return await call_next(request)

    def _extract_token(self, request: Request) -> Optional[str]:
        auth = request.headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            return auth.split(" ", 1)[1]
        return request.cookies.get(self._cookie_name)

    async def _verify(self, token: str) -> dict:
        try:
            header = pyjwt.get_unverified_header(token)
        except pyjwt.PyJWTError as exc:
            raise TokenInvalidError(str(exc)) from exc

        kid = header.get("kid")
        keys = await self._cache.get_keys()
        jwk = next((k for k in keys if k["kid"] == kid), None)
        if jwk is None:
            raise TokenInvalidError(f"kid desconhecido: {kid}")

        pubkey = _jwk_to_pubkey(jwk)
        try:
            return pyjwt.decode(token, pubkey, algorithms=["RS256"], issuer=self._issuer)
        except pyjwt.PyJWTError as exc:
            raise TokenInvalidError(str(exc)) from exc


def _wants_html(request: Request) -> bool:
    # /api/* sempre é JSON (contrato de API independe de header).
    if request.url.path.startswith("/api/"):
        return False
    # Top-level navigation no browser sempre seta Sec-Fetch-Mode=navigate.
    if request.headers.get("sec-fetch-mode") == "navigate":
        return True
    # Fallback: Accept negotiation. Só conta se text/html aparece antes
    # de application/json (curl/XHR usam Accept: */* ou JSON específico).
    accept = request.headers.get("accept", "")
    if "text/html" in accept and "application/json" not in accept.split(",")[0]:
        return True
    return False


class AuthRedirectMiddleware(BaseHTTPMiddleware):
    """Converte 401 em 302 pra `login_url?redirect_to=<url-original>` quando a
    request é navegação HTML. Pra API/XHR/POST mantém o 401 JSON original.

    Uso (em main.py do app):
        app.add_middleware(AuthRedirectMiddleware, login_url="https://apps.anmar.agr.br/login")
    """

    def __init__(self, app, login_url: str):
        super().__init__(app)
        self._login_url = login_url

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        if (
            response.status_code == 401
            and request.method in ("GET", "HEAD")
            and _wants_html(request)
        ):
            target = f"{self._login_url}?redirect_to={quote(str(request.url), safe='')}"
            return RedirectResponse(target, status_code=302)
        return response
