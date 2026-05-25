# AGENTS.md - BlessGuardian Backend

## Projeto

Repositorio Python/backend do BlessGuardian / AntiFraud Agent.

Objetivo: API FastAPI para receber mensagens capturadas pelo Android, analisar com LLM, persistir resultados no Aiven/PostgreSQL e expor historico para o app.

## Contexto tecnico

- Linguagem: Python
- Framework: FastAPI
- Servidor: Uvicorn
- LLM: LM Studio via OpenAI-compatible API
- Banco oficial: Aiven/PostgreSQL
- Branch de referencia atual: `refactor/device-id-fraud-logs`

## Endpoints principais

- `GET /health`
- `POST /detect`
- `GET /logs?device_id=...`

## Contrato Android -> Backend

Entrada correta de `/detect`:

```json
{
  "device_id": "uuid-anonimo-do-aparelho",
  "message_content": "texto da mensagem capturada",
  "source": "SMS"
}
```

Valores de `source` esperados pelo Android atual:

```text
SMS, WHATSAPP, TELEGRAM, INSTAGRAM, MANUAL, UNKNOWN
```

`MANUAL` representa mensagens coladas pelo usuario na aba `Analisar` do app Android. O endpoint `/detect` deve tratar esse caso igual aos demais: analisar, gravar em `fraud_logs` e retornar `status_db`.

Resposta esperada:

```json
{
  "status_db": true,
  "user_id": "uuid-interno-da-tabela-users",
  "analise": {
    "tentativa_fraude": true,
    "score": 0.91,
    "categoria": "phishing",
    "indicadores": ["urgencia", "pix", "link suspeito"],
    "veredito_curto": "Possivel golpe envolvendo Pix."
  }
}
```

Compatibilidade temporaria:

- `user_id` pode existir como fallback de entrada, mas o contrato novo do Android usa `device_id`.

## Modelo de dados

Relacao correta:

```text
Android device_id -> users.device_id
users.id -> fraud_logs.user_id
```

Tabela `users`:

- `id`: UUID PK
- `device_id`: varchar, recomendado como UNIQUE
- `vulnerability_score`: float8
- `created_at`: timestamp

Tabela `fraud_logs`:

- `id`: UUID PK
- `user_id`: UUID FK para `users.id`
- `content`: text
- `detected_at`: timestamp
- `explanation`: text
- `is_fraud`: bool
- `risk_score`: float8
- `source`: varchar

## Regras criticas

- `fraud_logs.user_id` deve receber `users.id`, nunca `device_id`.
- Se falhar a gravacao no Aiven, retornar `status_db=false`.
- Nao mascarar erro de persistencia como sucesso.
- Nao expor `AIVEN_URI`, `API_KEY_LM_STUDIO` ou outros segredos no codigo.
- Nao logar mensagens sensiveis sem mascaramento.
- Nao alterar contrato da API sem atualizar Android e documentacao.
- Nao assumir que a URL ngrok continua valida.

## Variaveis de ambiente

```text
AIVEN_URI
URL_MAUA_LM_STUDIO
API_KEY_LM_STUDIO
MODEL
```

## Checklist antes de entregar

- `/health` retorna healthy.
- `/docs` carrega.
- `/openapi.json` mostra `device_id`, `message_content` e `source`.
- `/detect` cria usuario quando `device_id` nao existe.
- `/detect` reutiliza usuario quando `device_id` ja existe.
- `/detect` grava `fraud_logs.user_id = users.id`.
- `/logs?device_id=...` retorna historico correto.
- `users.vulnerability_score` e atualizado de forma coerente.
- Erros de banco retornam `status_db=false` ou erro explicito.

## Consultas uteis no Aiven

```sql
SELECT id, device_id, vulnerability_score, created_at
FROM users
ORDER BY created_at DESC;
```

```sql
SELECT
  fl.id,
  u.device_id,
  fl.content,
  fl.risk_score,
  fl.is_fraud,
  fl.explanation,
  fl.source,
  fl.detected_at
FROM fraud_logs fl
JOIN users u ON u.id = fl.user_id
ORDER BY fl.detected_at DESC;
```

## Formato esperado de resposta

Quando atuar neste repositorio, responda preferencialmente com:

```markdown
## Diagnostico Backend
## Alteracoes propostas
## Contrato de API
## Banco / Aiven
## Riscos
## Testes
## Criterios de aceite
```
