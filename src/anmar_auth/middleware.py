import base64
from typing import Optional

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

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
