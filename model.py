from openai import OpenAI
from dotenv import load_dotenv
import os

load_dotenv()
client = OpenAI(
    base_url=os.getenv('BASE_URL_MAUA'),
    api_key=os.getenv('API_KEY_MAUA')
)

def treat_message_llm(mensagem):
    prompt_user = f"""
    Analise a seguinte mensagem e forneça o resultado no formato JSON especificado.
    Mensagem para análise:{mensagem}
    Formato de resposta esperado:
    {{
    "analise": {{
        "tentativa_fraude": "boolean",
        "score": "float",
        "categoria": "phishing | scam | seguro | outro",
        "indicadores": ["lista de pontos suspeitos identificados"],
        "veredito_curto": "string resumindo a decisão"
    }}
    }}
    """
    # Teste simples de chat completion
    response = client.chat.completions.create(
        model=os.getenv('MODEL'),  # o nome exato do modelo no LM Studio
        messages=[
            {"role": "system", "content": "Você é um sistema especialista em detecção de fraudes e análise de segurança cibernética. Sua tarefa é analisar mensagens enviadas por usuários para identificar indicadores de phishing, engenharia social, golpes financeiros ou intenções maliciosas.**Diretrizes de Análise:**1. Verifique a presença de links suspeitos ou encurtadores de URL.2. Analise o tom da mensagem (urgência excessiva, ameaças ou promessas de ganhos irreais).3. Identifique solicitações de dados sensíveis (senhas, tokens, CPF, dados bancários).4. Avalie a gramática e a consistência da comunicação em relação a comunicações oficiais.**Regras de Saída:**- Responda exclusivamente em formato JSON.- Não inclua explicações fora do bloco JSON.- Mantenha a chave score entre 0 (totalmente seguro) e 1 (fraude confirmada)."},
            {"role": "user", "content": prompt_user}
        ],
        temperature=0.2
    )

    return response.choices[0].message.content