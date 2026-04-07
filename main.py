import json
import re
import os
from database import register_scam_attempt


# 2. Dicionários Expandidos (Foco em Redução de Falsos Negativos)
KEYWORDS_BANCARIO = {
    "pix": 15, "p1x": 15, "banco": 5, "central": 8, "gerente": 10, 
    "conta": 5, "nubank": 8, "itau": 8, "bradesco": 8, "caixa": 8,
    "token": 12, "dispositivo": 10, "biometria": 10, "procuradoria": 15, 
    "receita": 15, "malha fina": 18, "serasa": 12, "spc": 12, 
    "cartorio": 15, "protesto": 15, "cpf": 8, "penhora": 20
}

KEYWORDS_URGENCIA = {
    "urgente": 15, "bloqueio": 20, "bloqueada": 20, "cancelamento": 15,
    "imediatamente": 12, "agora": 10, "suspensa": 15, "irregularidade": 15,
    "tentativa": 10, "acesso suspeito": 15, "evitar": 10, "multa": 12, 
    "expira": 15, "30 min": 15
}

KEYWORDS_REMOTO_SOCIAL = {
    "anydesk": 30, "teamviewer": 30, "suporte": 15, "instale": 20,
    "acesso remoto": 25, "modulo": 15, "mae": 10, "pai": 10, 
    "celular quebrou": 20, "numero novo": 15
}

# 3. Regex para Links (Essencial para Phishing)
URL_PATTERN = r"(https?://[^\s]+|bit\.ly/[^\s]+|t\.me/[^\s]+|tinyurl\.com/[^\s]+)"

def deep_normalize(text):
    """
    Remove tentativas de ofuscação como pontos e sublinhados entre letras.
    Ex: 'B.L.O.Q.U.E.I.O' -> 'bloqueio'
    """
    text = text.lower()
    # Remove pontos entre letras
    text = re.sub(r'(?<=[a-z])\.(?=[a-z])', '', text)
    # Remove sublinhados entre letras
    text = re.sub(r'(?<=[a-z])_(?=[a-z])', '', text)
    # Normaliza variações comuns de caracteres
    text = text.replace('p1x', 'pix').replace('p|x', 'pix').replace('p_i_x', 'pix')
    return text

def analyze_heuristic_v2(text):
    score = 0
    # Normalizamos o texto ANTES de buscar as keywords
    clean_text = deep_normalize(text)
    
    # Unifica todos os dicionários para a soma
    all_weights = {**KEYWORDS_BANCARIO, **KEYWORDS_URGENCIA, **KEYWORDS_REMOTO_SOCIAL}
    
    # 1. Soma de Keywords
    for word, weight in all_weights.items():
        if word in clean_text:
            score += weight

    # 2. Verificação de Links (Soma bônus de risco)
    if re.search(URL_PATTERN, text.lower()):
        score += 15

    # 3. Classificação
    final_score = min(score, 100)
    is_fraud = final_score >= 55 # Threshold ajustado para as novas keywords
    
    if final_score > 75:
        level = "CRÍTICO"
    elif is_fraud:
        level = "ALTO"
    else:
        level = "BAIXO"
        
    return final_score, is_fraud, level



def main():

    if not os.path.exists('log.json'):
        print("Arquivo log.json não encontrado.")
        return

    with open('log.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
        messages = data if isinstance(data, list) else [data]

    print("--- Processando Mensagens e Salvando no Aiven ---")
    for entry in messages:
        content = entry.get('message_content', '')
        user = entry.get('user_id', 'local_test')
        
        # Chama sua função de análise (Exemplo da Opção 2 ou 3)
        score, is_fraud, level = analyze_heuristic_v2(content)

        # REGISTRO VIA MÓDULO SEPARADO
        success = register_scam_attempt(user, content, score, level, is_fraud)
        
        db_status = "SALVO" if success else "ERRO DB"
        print(f"[{level}] | Score: {score} |{db_status} | Msg: {content[:70]}...")

if __name__ == "__main__":
    main()