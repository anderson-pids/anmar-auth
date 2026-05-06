from functools import wraps

from fastapi import HTTPException, Request


def _get_user(request: Request) -> dict:
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(status_code=401, detail="não autenticado")
    return user


def require_auth(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        request: Request | None = next((a for a in args if isinstance(a, Request)), None) or kwargs.get("request")
        if request is None:
            raise RuntimeError("require_auth precisa de Request no handler")
        _get_user(request)
        return await func(*args, **kwargs)
    return wrapper


def require_role(*roles: str):
    def deco(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request: Request | None = next((a for a in args if isinstance(a, Request)), None) or kwargs.get("request")
            if request is None:
                raise RuntimeError("require_role precisa de Request no handler")
            user = _get_user(request)
            if user.get("role") not in roles:
                raise HTTPException(status_code=403, detail="role insuficiente")
            return await func(*args, **kwargs)
        return wrapper
    return deco


def require_permission(permission: str):
    def deco(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request: Request | None = next((a for a in args if isinstance(a, Request)), None) or kwargs.get("request")
            if request is None:
                raise RuntimeError("require_permission precisa de Request no handler")
            user = _get_user(request)
            if permission not in user.get("permissions", []):
                raise HTTPException(status_code=403, detail=f"permissão ausente: {permission}")
            return await func(*args, **kwargs)
        return wrapper
    return deco


def require_self_or_permission(funcionario_id_param: str, permission: str):
    def deco(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request: Request | None = next((a for a in args if isinstance(a, Request)), None) or kwargs.get("request")
            if request is None:
                raise RuntimeError("require_self_or_permission precisa de Request no handler")
            user = _get_user(request)
            target_id = str(kwargs.get(funcionario_id_param, ""))
            if user.get("funcionario_id") == target_id:
                return await func(*args, **kwargs)
            if permission in user.get("permissions", []):
                return await func(*args, **kwargs)
            raise HTTPException(status_code=403, detail="acesso negado")
        return wrapper
    return deco
