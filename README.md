# BlessGuardian | Backend

> API de detecção de fraudes em mensagens, com análise por LLM e persistência em DynamoDB.

---

## Sobre o projeto

Este é o backend do **AntiFraud Agent**, aplicação desenvolvida como Trabalho de Conclusão de Curso (TCC) do curso de Ciências da Computação do **Instituto Mauá de Tecnologia (IMT)**.

O backend recebe mensagens capturadas pelo app Android, submete a análise a um modelo de linguagem (LLM) hospedado em LM Studio na máquina da Mauá, persiste o resultado no DynamoDB e expõe o histórico oficial para o app consumir.

---

## Equipe

| Nome | Papel |
|---|---|
| Ramon Santos Pereira | Desenvolvedor |
| Luiz Miguel Seixeiro | Desenvolvedor |
| Mitchell Miyake | Desenvolvedor |

**Orientador:** Prof. Rodrigo Bossini Tavares

---

## Arquitetura

```
[App Android]
      │
      │ POST /detect
      │ { device_id, message_content, source }
      ▼
[FastAPI em AWS ECS]
      │
      ├── treat_message_llm()      → LM Studio (OpenAI-compatible)
      │     └── retorna análise: score, categoria, indicadores, veredito
      │
      └── register_fraud_log()     → DynamoDB (bless_guardian_tcc)
            └── grava log oficial, deriva user_id via uuid5(device_id)

[App Android] ◄── GET /logs?device_id=... ─── [FastAPI] ─── [DynamoDB]
```

---

## Endpoints

| Método | Rota | Descrição |
|---|---|---|
| GET | `/health` | Verifica disponibilidade — retorna `{ "status": "healthy" }` |
| POST | `/detect` | Recebe mensagem, analisa via LLM e persiste no DynamoDB (status 201) |
| GET | `/logs` | Retorna histórico oficial filtrado por `device_id` (com `limit` e `offset`) |
| GET | `/docs` | Documentação OpenAPI interativa (Swagger UI) |

### Contrato `POST /detect`

Entrada:

```json
{
  "device_id": "uuid-anonimo-do-aparelho",
  "message_content": "texto da mensagem capturada",
  "source": "sms"
}
```

Saída:

```json
{
  "status_db": true,
  "user_id": "uuid-v5-derivado-do-device-id",
  "analise": {
    "tentativa_fraude": true,
    "score": 0.87,
    "categoria": "phishing",
    "indicadores": ["link encurtado", "urgencia"],
    "veredito_curto": "Provavel golpe de phishing"
  }
}
```

`source` aceito em minúsculas: `sms`, `whatsapp`, `telegram`, `instagram`, `manual`, `unknown`.

### Contrato `GET /logs?device_id=...&limit=50&offset=0`

```json
{
  "status": "success",
  "total_logs": 42,
  "data": [
    {
      "id": "uuid-v4",
      "user_id": "uuid-v5",
      "device_id": "...",
      "content": "...",
      "source": "whatsapp",
      "is_fraud": true,
      "risk_score": 0.87,
      "explanation": "...",
      "detected_at": "2026-05-25T14:41:15.517122+00:00"
    }
  ]
}
```

---

## Stack

- **Linguagem:** Python 3.11+
- **Framework HTTP:** FastAPI + Uvicorn
- **Banco oficial:** AWS DynamoDB (tabela `bless_guardian_tcc`)
- **LLM:** LM Studio (OpenAI-compatible) hospedado na máquina da Mauá
- **Hospedagem:** AWS ECS (containerizado)
- **Endpoint produção:** `https://bl-226178fb7921413cab6e2f261d27f9c2.ecs.us-east-1.on.aws`

---

## Estrutura do projeto

```
fraud_message_detection/
├── api.py                 → FastAPI app, rotas /health /detect /logs
├── database.py            → cliente DynamoDB + funções de persistência
├── fraud_detection.py     → orquestração da análise de fraude
├── model.py               → cliente do LM Studio e prompt do LLM
├── test.py                → testes manuais / smoke
├── AGENTS.md              → instruções técnicas para agentes/devs
└── log.json               → log local (auxiliar)
```

---

## Banco de dados (DynamoDB)

Tabela única: `bless_guardian_tcc`

- **Partition Key:** `user_id` (UUID v5 derivado do `device_id` via `uuid5(NAMESPACE_OID, device_id)`)
- **Sort Key:** `detected_at` (ISO 8601 UTC, ex: `2026-05-25T14:41:15.517122+00:00`)

Atributos:

| Campo | Tipo | Descrição |
|---|---|---|
| `id` | String | UUID v4 do log |
| `device_id` | String | Identificador anônimo do aparelho |
| `content` | String | Texto analisado |
| `source` | String | `sms` \| `whatsapp` \| `telegram` \| `instagram` \| `manual` \| `unknown` |
| `is_fraud` | Bool | Veredito booleano do LLM |
| `risk_score` | Decimal | Score 0.0–1.0 |
| `explanation` | String | Justificativa do LLM |

A consulta por `user_id` é eficiente; varreduras sem partition key (`scan`) são caras — o Android sempre envia `device_id` para que o backend derive o `user_id` antes de consultar.

---

## Variáveis de ambiente

Crie um arquivo `.env` na raiz com:

```env
DYNAMO_TABLE_NAME=bless_guardian_tcc
AWS_REGION=us-east-1
URL_MAUA_LM_STUDIO=http://endereco-da-maquina-da-maua/v1
API_KEY_LM_STUDIO=chave-do-lm-studio
MODEL=nome-do-modelo-no-lm-studio
```

Credenciais AWS são resolvidas automaticamente pelo `boto3` via AWS SSO, variáveis de ambiente padrão (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) ou IAM Role quando rodando em ECS.

> Existe ainda uma variável `AIVEN_URI` herdada da arquitetura anterior. O caminho PostgreSQL/Aiven foi descontinuado e não é mais usado em produção, mas o código de fallback continua presente.

---

## Como executar

1. Clone o repositório
```bash
git clone https://github.com/BlessGuardian/fraud_message_detection.git
cd fraud_message_detection
```

2. Crie um ambiente virtual e instale as dependências
```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/Mac

pip install fastapi uvicorn boto3 python-dotenv openai psycopg2-binary
```

3. Configure o `.env` (ver seção acima)

4. Suba o servidor
```bash
uvicorn api:app --reload --host 0.0.0.0 --port 8000
```

5. Acesse `http://localhost:8000/docs` para a UI do Swagger

---

## Repositórios relacionados

- **App Android:** [anti-fraud-agent-android](https://github.com/BlessGuardian/anti-fraud-agent-android)
- **Site / Dashboard:** [bless-guardian-official](https://github.com/BlessGuardian/bless-guardian-official)

---

## Contexto acadêmico

**Instituição:** Instituto Mauá de Tecnologia (IMT)
**Curso:** Ciências da Computação
**Tipo:** Trabalho de Conclusão de Curso (TCC) — 2026
