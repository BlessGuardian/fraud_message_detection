import json
import os
import re
from openai import AsyncOpenAI
from dotenv import load_dotenv
load_dotenv()

# Usando o cliente assíncrono
client = AsyncOpenAI(
    base_url=os.getenv('URL_MAUA_LM_STUDIO'),
    api_key=os.getenv('API_KEY_LM_STUDIO') 
)

async def treat_message_llm(mensagem):
    prompt_system='''Você é um sistema especialista em detecção de fraudes e segurança cibernética. Sua única função é distinguir mensagens entre tentativas de fraude e mensagens legítimas e extrair um veredito técnico.

**Diretrizes de Análise:**
1. Links: Verifique URLs encurtadas, domínios suspeitos ou que imitam marcas reais.
2. Tom e Urgência: Identifique ameaças de bloqueio, senso de urgência falso ou promessas de dinheiro fácil.
3. Dados Sensíveis: Detecte solicitações de senhas, tokens (2FA), PIX, CPF ou dados bancários.
4. Engenharia Social: Avalie se o remetente tenta se passar por uma instituição oficial de forma inconsistente.

**Regras Rígidas de Saída:**
- O output deve ser EXCLUSIVAMENTE um objeto JSON válido.
- Não utilize formatação Markdown (como ```json).
- Não adicione saudações ou explicações fora do JSON.
'''

    prompt_user = f'''Analise a mensagem delimitada pelas tags <mensagem> e </mensagem>.

<mensagem>
{mensagem}
</mensagem>

Retorne a sua análise OBRIGATORIAMENTE nesta estrutura exata e ordem de chaves:
{{
    "raciocinio": "String explicando o passo a passo da sua análise e o motivo das suspeitas.",
    "indicadores": ["Lista de strings com os pontos suspeitos. Deixe vazio se for seguro."],
    "categoria": "phishing | scam | seguro | spam",
    "score": Float entre 0.0 (totalmente seguro) e 1.0 (fraude confirmada),
    "tentativa_fraude": Boolean (Deve ser true apenas se o score for >= 0.7),
    "veredito_curto": "String de no máximo 50 caracteres ideal para notificações push."
}}'''

    # Await inserido aqui para não bloquear a thread enquanto o LLM processa
    response = await client.chat.completions.create(
        model=os.getenv('MODEL'),  
        messages=[
            {"role": "system", "content": prompt_system},
            {"role": "user", "content": prompt_user}
        ],
        temperature=0.1
    )
    match = re.search(r'\{.*\}', response.choices[0].message.content, re.DOTALL)
    if match:
        json_str = match.group(0)
        return json.loads(json_str)
    return json.loads(response.choices[0].message.content)