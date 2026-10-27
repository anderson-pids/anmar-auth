import base64
from collections.abc import Mapping
from typing import Optional
from urllib.parse import quote
from uuid import UUID

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

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
    def __init__(
        self, app, jwks_url: str, issuer: str,
        cookie_name: str = "anmar_session", jwks_ttl: int = 3600,
        integration_audience: str | None = None,
        integration_routes: Mapping[tuple[str, str], str] | None = None,
    ):
        super().__init__(app)
        self._cache = JWKSCache(jwks_url, ttl=jwks_ttl)
        self._issuer = issuer
        self._cookie_name = cookie_name
        self._integration_audience = integration_audience
        self._integration_routes = dict(integration_routes or {})

    async def dispatch(self, request: Request, call_next):
        token = self._extract_token(request)
        if token:
            try:
                claims = await self._verify(token)
                if claims.get("token_use") == "integration":
                    auth = request.headers.get("authorization", "")
                    if not auth.lower().startswith("bearer "):
                        raise TokenInvalidError("integração exige Bearer")
                    permission = self._integration_routes.get((request.method, request.url.path))
                    if permission is None or permission not in claims["permissions"]:
                        return JSONResponse({"detail": "acesso negado"}, status_code=403)
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
            try:
                claims = pyjwt.decode(token, pubkey, algorithms=["RS256"], issuer=self._issuer)
            except pyjwt.InvalidAudienceError:
                if not self._integration_audience:
                    raise
                claims = pyjwt.decode(
                    token, pubkey, algorithms=["RS256"], issuer=self._issuer,
                    audience=self._integration_audience,
                    options={
                        "strict_aud": True,
                        "require": ["iss", "aud", "sub", "token_use", "role", "fazenda",
                                    "permissions", "scope", "iat", "exp", "jti"],
                    },
                )
                self._validate_integration_claims(claims)
                return claims
            # An integration without aud must never become a legacy human session.
            if claims.get("token_use") == "integration" or claims.get("role") == "integration":
                raise TokenInvalidError("integração exige audience")
            return claims
        except (pyjwt.PyJWTError, TypeError) as exc:
            # PyJWT 2.9 raises TypeError for malformed numeric date claims.
            raise TokenInvalidError(str(exc)) from exc

    @staticmethod
    def _validate_integration_claims(claims: dict) -> None:
        if claims["token_use"] != "integration" or claims["role"] != "integration":
            raise TokenInvalidError("tipo de token inválido")
        try:
            UUID(claims["sub"])
        except (ValueError, TypeError, AttributeError) as exc:
            raise TokenInvalidError("sub de integração inválido") from exc
        if claims["fazenda"] not in ("serra-branca", "renascer"):
            raise TokenInvalidError("fazenda de integração inválida")
        permissions = claims["permissions"]
        if (
            not isinstance(permissions, list) or not permissions
            or any(not isinstance(p, str) or not p or any(c.isspace() for c in p) for p in permissions)
            or len(set(permissions)) != len(permissions)
        ):
            raise TokenInvalidError("permissões de integração inválidas")
        scope = claims["scope"]
        if not isinstance(scope, str) or scope != " ".join(permissions):
            raise TokenInvalidError("scope incompatível com permissões")
        if (
            type(claims["iat"]) is not int or type(claims["exp"]) is not int
            or not 0 < claims["exp"] - claims["iat"] <= 300
        ):
            raise TokenInvalidError("validade de integração inválida")
        if not isinstance(claims["jti"], str) or not claims["jti"].strip():
            raise TokenInvalidError("jti de integração inválido")


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
