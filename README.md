# anmar-auth

Cliente FastAPI para validar JWT/JWKS do anmar-apps gateway.

## Install

```bash
pip install git+https://github.com/anderson-pids/anmar-auth.git@v0.3.0
```

## Use

Por padrão, apps novos aceitam apenas sessões humanas existentes, sem `aud`.
Configure o JWKS e o issuer do gateway no ambiente:

```python
import os

from fastapi import FastAPI, Request
from anmar_auth import AnmarAuthMiddleware, require_auth

app = FastAPI()
app.add_middleware(
    AnmarAuthMiddleware,
    jwks_url=os.environ["ANMAR_JWKS_URL"],
    issuer=os.environ["ANMAR_JWT_ISSUER"],
)

@app.get("/api/me")
@require_auth
async def me(request: Request):
    return request.state.user
```

O middleware preenche `request.state.user`; tokens ausentes ou inválidos deixam
esse valor como `None`. Use `require_auth` (ou os decorators de permissão/role)
nas rotas protegidas para responder 401. Sessões humanas continuam aceitas via
Bearer ou cookie `anmar_session`.

## Integrações

Integrações exigem ativação explícita por app. No Anmar Leite, configure:

```python
app.add_middleware(
    AnmarAuthMiddleware,
    jwks_url=os.environ["ANMAR_JWKS_URL"],
    issuer=os.environ["ANMAR_JWT_ISSUER"],
    integration_audience="anmar-leite",
    integration_routes={
        ("GET", "/api/turnos/atual"): "app:leite:read",
        ("GET", "/api/ordenhas"): "app:leite:read",
    },
)
```

Use essa configuração no lugar da configuração padrão, uma única vez por app.
`integration_routes` associa método HTTP e caminho exatos à permissão exigida.
Sem allowlist, nenhuma rota aceita integração. Um token de integração válido
recebe 403 em qualquer rota fora dela, incluindo páginas HTML, documentação,
rotas desconhecidas e mutações. O caminho não inclui a query string.

Tokens de integração são aceitos apenas no header `Authorization: Bearer ...`,
nunca em cookies. A verificação exige assinatura RS256, issuer configurado,
`aud` como string exatamente igual à audiência do app, `sub` UUID,
`token_use=integration`, `role=integration`, uma `fazenda` (`serra-branca` ou
`renascer`), `permissions` como lista não vazia de strings únicas, `scope` igual
às permissões unidas por espaço, `jti` não vazio e `iat`/`exp` inteiros com
validade máxima de 300 segundos. Não há tolerância adicional de relógio.
Para o Leite, o gateway emite `permissions=["app:leite:read"]` e
`scope="app:leite:read"`.

O app deve restringir todas as consultas à `fazenda` autenticada em
`request.state.user`, sem aceitar troca de fazenda por query ou payload.
Permissões e parâmetros fornecidos pelo cliente não substituem os claims
verificados. A role `integration` não concede privilégios de admin/poweruser.

A validação é local via JWKS, sem introspecção por requisição. Revogar a
credencial impede novas emissões no gateway; tokens já emitidos podem continuar
válidos por até 5 minutos, até seu vencimento. Apps sem ativação explícita
rejeitam esses tokens e preservam suas sessões humanas sem `aud`.

## License

Privado / Proprietário Anderson Pimentel.
