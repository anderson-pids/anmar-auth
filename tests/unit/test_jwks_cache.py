import pytest
import respx
import httpx

from anmar_auth.jwks_cache import JWKSCache
from anmar_auth.exceptions import JWKSFetchError


@pytest.mark.asyncio
async def test_jwks_cache_busca_e_cacheia():
    fake_jwks = {"keys": [{"kty": "RSA", "kid": "v1", "n": "x", "e": "AQAB", "alg": "RS256", "use": "sig"}]}

    with respx.mock:
        respx.get("https://apps.anmar.agr.br/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=fake_jwks)
        )
        cache = JWKSCache("https://apps.anmar.agr.br/.well-known/jwks.json", ttl=3600)
        keys = await cache.get_keys()
        assert keys[0]["kid"] == "v1"

        # segunda chamada não bate na rede
        keys2 = await cache.get_keys()
        assert keys2[0]["kid"] == "v1"
        assert respx.calls.call_count == 1


@pytest.mark.asyncio
async def test_jwks_cache_falha_retorna_erro():
    with respx.mock:
        respx.get("https://apps.anmar.agr.br/.well-known/jwks.json").mock(
            return_value=httpx.Response(500)
        )
        cache = JWKSCache("https://apps.anmar.agr.br/.well-known/jwks.json", ttl=3600)
        with pytest.raises(JWKSFetchError):
            await cache.get_keys()
