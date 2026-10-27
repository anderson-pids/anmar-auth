import json
import time
from uuid import uuid4

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request
from starlette.testclient import TestClient

from anmar_auth import AnmarAuthMiddleware, require_auth

ISSUER = "https://issuer.test"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"
ROUTES = {
    ("GET", "/api/turnos/atual"): "app:leite:read",
    ("GET", "/api/ordenhas"): "app:leite:read",
}


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def claims():
    now = int(time.time())
    return {
        "iss": ISSUER,
        "sub": str(uuid4()),
        "token_use": "integration",
        "role": "integration",
        "fazenda": "serra-branca",
        "permissions": ["app:leite:read"],
        "scope": "app:leite:read",
        "aud": "anmar-leite",
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid4()),
    }


@pytest.fixture
def token(signing_key):
    def sign(claims):
        return jwt.encode(
            claims, signing_key, algorithm="RS256", headers={"kid": "test-key"}
        )

    return sign


@pytest.fixture
def client_factory(signing_key):
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key()))
    jwk["kid"] = "test-key"
    with respx.mock:
        respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json={"keys": [jwk]}))

        def create(*, opt_in=True, routes=ROUTES):
            app = FastAPI()
            options = (
                {"integration_audience": "anmar-leite", "integration_routes": routes}
                if opt_in
                else {}
            )
            app.add_middleware(
                AnmarAuthMiddleware, jwks_url=JWKS_URL, issuer=ISSUER, **options
            )

            async def protected(request: Request):
                return request.state.user

            for path in ["/api/turnos/atual", "/api/ordenhas", "/api/private"]:
                app.add_api_route(
                    path,
                    require_auth(protected),
                    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"],
                )

            @app.get("/")
            async def public_page():
                return {"public": True}

            return TestClient(app)

        yield create


@pytest.mark.parametrize("path", ["/api/turnos/atual", "/api/ordenhas"])
@pytest.mark.parametrize("fazenda", ["serra-branca", "renascer"])
def test_valid_integration_reads_allowed_routes(
    client_factory, token, claims, path, fazenda
):
    claims["fazenda"] = fazenda
    response = client_factory().get(
        path, headers={"Authorization": f"Bearer {token(claims)}"}
    )
    assert response.status_code == 200
    assert response.json()["role"] == "integration"
    assert response.json()["fazenda"] == fazenda


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/api/ordenhas"),
        ("PUT", "/api/ordenhas"),
        ("DELETE", "/api/ordenhas"),
        ("PATCH", "/api/ordenhas"),
        ("HEAD", "/api/ordenhas"),
        ("GET", "/api/private"),
        ("GET", "/"),
        ("GET", "/docs"),
        ("GET", "/missing"),
    ],
)
def test_valid_integration_denies_every_route_outside_allowlist(
    client_factory, token, claims, method, path
):
    response = client_factory().request(
        method, path, headers={"Authorization": f"Bearer {token(claims)}"}
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    "field,value",
    [
        ("aud", "anmar-rh"),
        ("aud", ["anmar-leite", "anmar-rh"]),
        ("aud", ["anmar-leite"]),
        ("token_use", "human"),
        ("role", "admin"),
        ("role", "poweruser"),
        ("fazenda", "all"),
        ("fazenda", ["serra-branca", "renascer"]),
        ("sub", "not-a-uuid"),
        ("permissions", "app:leite:read"),
        ("permissions", []),
        ("permissions", ["admin"]),
        ("scope", "app:leite:write"),
        ("scope", ["app:leite:read"]),
        ("iss", "https://other.test"),
        ("jti", ""),
        ("iat", []),
        ("iat", {}),
        ("exp", []),
        ("exp", {}),
        ("iat", True),
        ("exp", True),
        ("permissions", ["app:leite:read", "app:leite:read"]),
        ("permissions", ["app:leite:read", {}]),
    ],
)
def test_invalid_integration_claims_are_unauthenticated(
    client_factory, token, claims, field, value
):
    claims[field] = value
    response = client_factory().get(
        "/api/ordenhas", headers={"Authorization": f"Bearer {token(claims)}"}
    )
    assert response.status_code == 401


@pytest.mark.parametrize(
    "field",
    [
        "aud",
        "token_use",
        "role",
        "sub",
        "fazenda",
        "permissions",
        "scope",
        "iat",
        "exp",
        "jti",
    ],
)
def test_integration_requires_claims(client_factory, token, claims, field):
    del claims[field]
    response = client_factory().get(
        "/api/ordenhas", headers={"Authorization": f"Bearer {token(claims)}"}
    )
    assert response.status_code == 401


@pytest.mark.parametrize(
    "iat_offset,exp_offset", [(0, 301), (-400, -100), (30, 300), (0, 0)]
)
def test_integration_enforces_expiry_and_maximum_lifetime(
    client_factory, token, claims, iat_offset, exp_offset
):
    now = int(time.time())
    claims.update(iat=now + iat_offset, exp=now + exp_offset)
    response = client_factory().get(
        "/api/ordenhas", headers={"Authorization": f"Bearer {token(claims)}"}
    )
    assert response.status_code == 401


def test_integration_requires_bearer_not_cookie(client_factory, token, claims):
    client = client_factory()
    client.cookies.set("anmar_session", token(claims))
    assert client.get("/api/ordenhas").status_code == 401


def test_integration_requires_app_opt_in(client_factory, token, claims):
    response = client_factory(opt_in=False).get(
        "/api/ordenhas", headers={"Authorization": f"Bearer {token(claims)}"}
    )
    assert response.status_code == 401


def test_audience_alone_does_not_allow_any_route(client_factory, token, claims):
    response = client_factory(routes={}).get(
        "/api/ordenhas", headers={"Authorization": f"Bearer {token(claims)}"}
    )
    assert response.status_code == 403


def test_route_permission_must_be_granted(client_factory, token, claims):
    response = client_factory(routes={("GET", "/api/ordenhas"): "app:leite:write"}).get(
        "/api/ordenhas", headers={"Authorization": f"Bearer {token(claims)}"}
    )
    assert response.status_code == 403


@pytest.mark.parametrize("opt_in", [False, True])
@pytest.mark.parametrize("via_cookie", [False, True])
def test_legacy_human_sessions_are_preserved(client_factory, token, opt_in, via_cookie):
    human = {
        "iss": ISSUER,
        "sub": str(uuid4()),
        "role": "admin",
        "permissions": [],
        "exp": int(time.time()) + 3600,
    }
    client = client_factory(opt_in=opt_in)
    headers = {}
    if via_cookie:
        client.cookies.set("anmar_session", token(human))
    else:
        headers["Authorization"] = f"Bearer {token(human)}"
    response = client.post("/api/private", headers=headers)
    assert response.status_code == 200
    assert response.json()["role"] == "admin"


def test_human_with_audience_cannot_become_integration(client_factory, token, claims):
    del claims["token_use"]
    claims["role"] = "admin"
    response = client_factory().get(
        "/api/ordenhas", headers={"Authorization": f"Bearer {token(claims)}"}
    )
    assert response.status_code == 401


def test_missing_audience_cannot_escape_as_human_even_without_opt_in(
    client_factory, token, claims
):
    del claims["aud"]
    response = client_factory(opt_in=False).post(
        "/api/private", headers={"Authorization": f"Bearer {token(claims)}"}
    )
    assert response.status_code == 401


def test_invalid_bearer_cannot_fall_back_to_human_cookie_or_query(
    client_factory, token, claims
):
    human = {"iss": ISSUER, "sub": str(uuid4()), "role": "admin"}
    client = client_factory()
    client.cookies.set("anmar_session", token(human))
    claims["aud"] = "other-app"
    response = client.get(
        "/api/ordenhas?role=admin&fazenda=renascer",
        headers={"Authorization": f"Bearer {token(claims)}"},
    )
    assert response.status_code == 401


def test_signature_must_match_published_key(client_factory, claims):
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signed = jwt.encode(
        claims, wrong_key, algorithm="RS256", headers={"kid": "test-key"}
    )
    response = client_factory().get(
        "/api/ordenhas", headers={"Authorization": f"Bearer {signed}"}
    )
    assert response.status_code == 401


def test_integration_cannot_use_symmetric_signature(client_factory, claims):
    signed = jwt.encode(
        claims,
        "test-only-symmetric-key-that-is-long-enough",
        algorithm="HS256",
        headers={"kid": "test-key"},
    )
    response = client_factory().get(
        "/api/ordenhas", headers={"Authorization": f"Bearer {signed}"}
    )
    assert response.status_code == 401
