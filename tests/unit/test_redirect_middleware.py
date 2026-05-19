"""Testa AuthRedirectMiddleware: converte 401 em redirect pro login_url quando
a request é navegação HTML; mantém JSON 401 pra API/XHR/POST."""
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI, HTTPException
from starlette.testclient import TestClient

from anmar_auth.middleware import AuthRedirectMiddleware

LOGIN_URL = "https://apps.anmar.agr.br/login"


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(AuthRedirectMiddleware, login_url=LOGIN_URL)

    @app.get("/minhas")
    async def minhas():
        raise HTTPException(status_code=401, detail="não autenticado")

    @app.post("/api/despesas")
    async def api_post():
        raise HTTPException(status_code=401, detail="não autenticado")

    @app.get("/api/me")
    async def api_get():
        raise HTTPException(status_code=401, detail="não autenticado")

    @app.get("/abrir")
    async def abrir():
        return {"ok": True}

    @app.get("/ruim")
    async def ruim():
        raise HTTPException(status_code=400, detail="ruim")

    return app


@pytest.fixture
def client():
    return TestClient(_app(), follow_redirects=False)


def test_html_get_401_redireciona_pro_login(client):
    r = client.get("/minhas", headers={"Accept": "text/html,*/*"})
    assert r.status_code == 302
    parsed = urlparse(r.headers["location"])
    assert parsed.scheme == "https"
    assert parsed.netloc == "apps.anmar.agr.br"
    assert parsed.path == "/login"
    qs = parse_qs(parsed.query)
    assert "redirect_to" in qs
    assert "/minhas" in qs["redirect_to"][0]


def test_html_get_redirect_preserva_query_da_origem(client):
    r = client.get("/minhas?mes=05&ano=2026", headers={"Accept": "text/html"})
    assert r.status_code == 302
    redirect_to = parse_qs(urlparse(r.headers["location"]).query)["redirect_to"][0]
    # redirect_to deve preservar query string da request original
    assert "mes=05" in redirect_to
    assert "ano=2026" in redirect_to


def test_json_get_401_mantem_json(client):
    r = client.get("/api/me", headers={"Accept": "application/json"})
    assert r.status_code == 401
    assert r.json()["detail"] == "não autenticado"


def test_api_path_sempre_json_mesmo_com_accept_html(client):
    # /api/* devem manter contrato JSON mesmo se Accept include text/html
    # (alguns browsers/curl mandam Accept: */* genérico)
    r = client.get("/api/me", headers={"Accept": "text/html,*/*"})
    assert r.status_code == 401
    assert r.json()["detail"] == "não autenticado"


def test_post_401_nao_redireciona(client):
    # POST de form/XHR não pode virar redirect (browser não preserva body).
    r = client.post("/api/despesas", headers={"Accept": "text/html"})
    assert r.status_code == 401


def test_sec_fetch_navigate_redireciona_mesmo_sem_accept_html(client):
    # Browser top-level nav sempre seta Sec-Fetch-Mode=navigate.
    r = client.get("/minhas", headers={"Accept": "*/*", "Sec-Fetch-Mode": "navigate"})
    assert r.status_code == 302


def test_response_200_passa_inalterada(client):
    r = client.get("/abrir", headers={"Accept": "text/html"})
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_400_nao_e_alterado(client):
    # Só 401 dispara redirect; outros 4xx (400/403/404) seguem normal.
    r = client.get("/ruim", headers={"Accept": "text/html"})
    assert r.status_code == 400
    assert r.json()["detail"] == "ruim"
