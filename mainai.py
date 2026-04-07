import os
import re
import json
from transformers import pipeline
from database import register_scam_attempt


# 2. Inicializar IA (BERT Multilingue)
print("Carregando IA de análise de intenção...")
classifier = pipeline("sentiment-analysis", model="nlptown/bert-base-multilingual-uncased-sentiment")

# 3. Pesos para soma de Score (Opção 3 Adaptada)
# 1. Institucional e Autoridade (Simula confiança e medo)
KEYWORDS_BANCARIO = {
    "pix": 15, "p1x": 15, "banco": 5, "central": 8, "gerente": 10, 
    "conta": 5, "nubank": 8, "itau": 8, "bradesco": 8, "caixa": 8,
    "token": 12, "dispositivo": 10, "biometria": 10, "procuradoria": 15, 
    "receita": 15, "malha fina": 18, "serasa": 12, "spc": 12, 
    "cartorio": 15, "protesto": 15, "cpf": 8, "penhora": 20, "cartao":10
}

# 2. Gatilhos de Urgência e Coação (Ataque Psicológico)
KEYWORDS_URGENCIA = {
    "urgente": 15, "bloqueio": 20, "bloqueada": 20, "cancelamento": 15,
    "imediatamente": 12, "agora": 10, "suspensa": 15, "irregularidade": 15,
    "tentativa": 10, "acesso suspeito": 15, "evitar": 10, "multa": 12, 
    "expira": 15, "prazo": 10, "30 min": 15, "hoje": 5
}

# 3. Engenharia Social de Interação (Mão Fantasma / Falso Filho)
KEYWORDS_REMOTO = {
    "anydesk": 30, "teamviewer": 30, "suporte": 15, "instale": 20,
    "acesso remoto": 25, "modulo": 15, "mae": 10, "pai": 10, 
    "celular quebrou": 20, "numero novo": 15, "conserto": 10
}

# 4. Regex para detecção de Links
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

def analyze_ai_hybrid_v3(text):
    score = 0
    clean_text = deep_normalize(text)
    
    # --- PASSO A: Análise de Intenção via IA ---
    # 1 ou 2 estrelas indicam teor negativo/urgente/agressivo
    result = classifier(clean_text[:512])[0]
    if result['label'] == '1 star': 
        score += 40
    elif result['label'] == '2 stars': 
        score += 20

    # --- PASSO B: Soma de Keywords ---
    # Unificando as listas para somar ao score 0 inicial
    all_keywords = {**KEYWORDS_BANCARIO, **KEYWORDS_URGENCIA, **KEYWORDS_REMOTO}
    for word, weight in all_keywords.items():
        if word in clean_text:
            score += weight

    # --- PASSO C: Verificação de Links ---
    if re.search(URL_PATTERN, clean_text):
        score += 15

    # --- PASSO D: Classificação Final ---
    final_score = min(score, 100) # Garante que não passe de 100 para o DB
    is_fraud = final_score >= 55
    
    # Define o risk_level baseado no score
    if final_score > 75:
        level = "CRÍTICO"
    elif is_fraud:
        level = "ALTO"
    else:
        level = "BAIXO"
    
    return final_score, is_fraud, level


def main():
    # 1. Garante que a tabela existe (bom para a primeira execução)
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
        score, is_fraud, level = analyze_ai_hybrid_v3(content)
        

        # REGISTRO VIA MÓDULO SEPARADO
        success = register_scam_attempt(user, content, score, level, is_fraud)
        
        color = "\033[91m" if is_fraud else "\033[92m"
        db_status = "SALVO" if success else "ERRO DB"
        print(f"{color}[{level}] | Score: {score}\033[0m | {db_status} | Msg: {content[:70]}...")

if __name__ == "__main__":
    main()