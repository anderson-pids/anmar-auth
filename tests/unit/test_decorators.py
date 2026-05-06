from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from anmar_auth.decorators import require_permission, require_role


def _build_app():
    app = FastAPI()

    @app.get("/admin-only")
    @require_role("admin")
    async def admin_only(request: Request):
        return {"ok": True}

    @app.get("/perm-rebanho")
    @require_permission("app:rebanho:manage")
    async def perm_rebanho(request: Request):
        return {"ok": True}

    @app.middleware("http")
    async def fake_user(request: Request, call_next):
        # role/perm injetados via header pra simplificar teste
        role = request.headers.get("x-test-role")
        perms = request.headers.get("x-test-perms", "").split(",") if request.headers.get("x-test-perms") else []
        request.state.user = {"role": role, "permissions": perms} if role else None
        return await call_next(request)

    return app


def test_require_role_passa_admin():
    c = TestClient(_build_app())
    r = c.get("/admin-only", headers={"x-test-role": "admin"})
    assert r.status_code == 200


def test_require_role_falha_user():
    c = TestClient(_build_app())
    r = c.get("/admin-only", headers={"x-test-role": "user"})
    assert r.status_code == 403


def test_require_permission_passa_se_tem():
    c = TestClient(_build_app())
    r = c.get("/perm-rebanho", headers={"x-test-role": "poweruser", "x-test-perms": "app:rebanho:manage"})
    assert r.status_code == 200


def test_require_permission_falha_se_nao_tem():
    c = TestClient(_build_app())
    r = c.get("/perm-rebanho", headers={"x-test-role": "poweruser"})
    assert r.status_code == 403


def test_sem_user_retorna_401():
    c = TestClient(_build_app())
    r = c.get("/admin-only")
    assert r.status_code == 401
