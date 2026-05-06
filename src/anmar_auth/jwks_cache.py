import asyncio
import time
from typing import Any

import httpx

from anmar_auth.exceptions import JWKSFetchError


class JWKSCache:
    def __init__(self, jwks_url: str, ttl: int = 3600):
        self._url = jwks_url
        self._ttl = ttl
        self._keys: list[dict[str, Any]] | None = None
        self._fetched_at = 0.0
        self._lock = asyncio.Lock()

    async def get_keys(self) -> list[dict[str, Any]]:
        now = time.time()
        if self._keys is not None and now - self._fetched_at < self._ttl:
            return self._keys
        async with self._lock:
            if self._keys is not None and time.time() - self._fetched_at < self._ttl:
                return self._keys
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(self._url, timeout=5.0)
                    resp.raise_for_status()
                self._keys = resp.json()["keys"]
                self._fetched_at = time.time()
                return self._keys
            except (httpx.HTTPError, KeyError) as exc:
                raise JWKSFetchError(str(exc)) from exc

    def get_key_by_kid(self, kid: str) -> dict[str, Any] | None:
        if self._keys is None:
            return None
        for k in self._keys:
            if k["kid"] == kid:
                return k
        return None
