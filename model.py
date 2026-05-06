import json
import os
import re
from openai import OpenAI
from dotenv import load_dotenv
load_dotenv()

client = OpenAI(
    base_url=os.getenv('URL_MAUA_LM_STUDIO'),
    api_key=os.getenv('API_KEY_LM_STUDIO') 
)

def treat_message_llm(mensagem):
    prompt_system='''
    Você é um sistema especialista em detecção de fraudes e análise de segurança cibernética. Sua tarefa é analisar mensagens enviadas por usuários para identificar indicadores de phishing, engenharia social, golpes financeiros ou intenções maliciosas.

    **Diretrizes de Análise:**
    1. Verifique a presença de links suspeitos ou encurtadores de URL.
    2. Analise o tom da mensagem (urgência excessiva, ameaças ou promessas de ganhos irreais).
    3. Identifique solicitações de dados sensíveis (senhas, tokens, CPF, dados bancários).
    4. Avalie a gramática e a consistência da comunicação em relação a comunicações oficiais.

    **Regras de Saída:**
    - Responda exclusivamente em formato JSON.
    - Não inclua explicações fora do bloco JSON.
    - Não use blocos de código Markdown
    - Mantenha a chave "score" entre 0 (totalmente seguro) e 1 (fraude confirmada).
    - O veredito curto deve ser curto o suficiente para caber em notifações de celular
    '''
    prompt_user=f'''
    Analise a seguinte mensagem e forneça o resultado no formato JSON especificado.

    **Mensagem para análise:**
    {mensagem}

    **Formato de resposta esperado:**
     {{
        "tentativa_fraude": boolean,
        "score": float, 
        "categoria": "phishing | scam | seguro | outro",
        "indicadores": ["lista de pontos suspeitos identificados"],
        "veredito_curto": "string resumindo a decisão"
    }}
    '''

    response = client.chat.completions.create(
        model=os.getenv('MODEL'),  # o nome exato do modelo no LM Studio
        messages=[
            {"role": "system", "content": prompt_system},
            {"role": "user", "content": prompt_user}
        ],
        temperature=0.2
    )
    match = re.search(r'\{.*\}', response.choices[0].message.content, re.DOTALL)
    if match:
        json_str = match.group(0)
        return json.loads(json_str)
    return json.loads(response.choices[0].message.content)